"""NVD CVE sync — pulls real advisories per fleet tool and matches installed versions."""
from __future__ import annotations

import asyncio
import logging
import os
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Awaitable, Callable

import httpx
from packaging.version import Version, InvalidVersion

log = logging.getLogger("secmaster.nvd")

NVD_URL = os.environ["NVD_API_URL"]
PAGE_SIZE = 500
MAX_PAGES = 4
RECENT_DAYS = 90
MAX_DISPATCH = 15
_lock = asyncio.Lock()

# fleet tool name -> CPE product name
CPE_ALIASES = {
    "burpsuite": "burp_suite", "wazuh-agent": "wazuh", "volatility3": "volatility",
    "vscode": "visual_studio_code", "python3": "python", "metasploit": "metasploit",
    "impacket": "impacket", "netexec": "netexec", "evil-winrm": "evil-winrm",
    "sliver": "sliver", "bloodhound": "bloodhound", "osquery": "osquery",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(s: str) -> str:
    return (s or "").lower().replace("-", "_")


def _parse_ver(s: str | None) -> Version | None:
    if not s:
        return None
    try:
        return Version(s)
    except InvalidVersion:
        nums = re.findall(r"\d+", s)
        if not nums:
            return None
        try:
            return Version(".".join(nums[:4]))
        except InvalidVersion:
            return None


def _cpe_parts(criteria: str) -> tuple[str, str]:
    parts = criteria.split(":")
    return (parts[4] if len(parts) > 4 else "", parts[5] if len(parts) > 5 else "")


def _range_text(m: dict) -> str:
    bits = []
    if m.get("versionStartIncluding"): bits.append(f">= {m['versionStartIncluding']}")
    if m.get("versionStartExcluding"): bits.append(f"> {m['versionStartExcluding']}")
    if m.get("versionEndIncluding"): bits.append(f"<= {m['versionEndIncluding']}")
    if m.get("versionEndExcluding"): bits.append(f"< {m['versionEndExcluding']}")
    if bits:
        return " ".join(bits)
    _, v = _cpe_parts(m.get("criteria", ""))
    return "all versions" if v in ("*", "-", "") else f"== {v}"


def _match_vulnerable(m: dict, ver: Version) -> bool:
    if not m.get("vulnerable", True):
        return False
    _, crit_ver = _cpe_parts(m.get("criteria", ""))
    if crit_ver not in ("*", "-", ""):
        cv = _parse_ver(crit_ver)
        return cv is not None and cv == ver
    checks = (
        ("versionStartIncluding", lambda b: ver >= b),
        ("versionStartExcluding", lambda b: ver > b),
        ("versionEndIncluding", lambda b: ver <= b),
        ("versionEndExcluding", lambda b: ver < b),
    )
    for key, fn in checks:
        if m.get(key):
            bound = _parse_ver(m[key])
            if bound is None or not fn(bound):
                return False
    return True


def _severity(cve: dict) -> tuple[str, float]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            data = m.get("cvssData") or {}
            score = float(data.get("baseScore") or 0)
            sev = (data.get("baseSeverity") or m.get("baseSeverity") or "").lower()
            if not sev:
                sev = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            return sev, score
    return "low", 0.0


def _description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _fleet_inventory(workstations: list[dict]) -> dict[str, dict[str, set[str]]]:
    inv: dict[str, dict[str, set[str]]] = {}
    for ws in workstations:
        for t in ws.get("tools") or []:
            if not isinstance(t, dict):
                continue
            name, ver = t.get("name"), t.get("version")
            if not name or not ver or ver == "unknown":
                continue
            inv.setdefault(name, {}).setdefault(ver, set()).add(ws["id"])
    return inv


async def _fetch_tool(client: httpx.AsyncClient, product: str) -> list[dict]:
    out: list[dict] = []
    start = 0
    for _ in range(MAX_PAGES):
        params = {"virtualMatchString": f"cpe:2.3:a:*:{product}", "resultsPerPage": PAGE_SIZE, "startIndex": start}
        r = await client.get(NVD_URL, params=params)
        if r.status_code == 404:
            break
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities") or []
        out.extend(v["cve"] for v in vulns if v.get("cve"))
        start += len(vulns)
        if start >= int(data.get("totalResults") or 0) or not vulns:
            break
        await asyncio.sleep(0.7)
    return out


def _remediation(tool: str) -> str:
    return f"nix flake update && sudo nixos-rebuild switch   # nixos\nwinget upgrade {tool}   # windows"


async def sync(db, dispatch: Callable[[str, dict], Awaitable] | None = None) -> dict:
    if _lock.locked():
        return {"skipped": True, "reason": "sync already running"}
    async with _lock:
        return await _sync(db, dispatch)


async def _sync(db, dispatch) -> dict:
    api_key = os.environ.get("NVD_API_KEY", "")
    await db.meta.update_one({"key": "nvd_sync"}, {"$set": {
        "status": "running", "started_at": _now(), "finished_at": None, "error": None,
    }}, upsert=True)
    workstations = await db.workstations.find({}, {"_id": 0, "id": 1, "tools": 1}).to_list(1000)
    inventory = _fleet_inventory(workstations)
    previous = {c["cve_id"]: c async for c in db.cves.find({"source": "nvd"}, {"_id": 0, "cve_id": 1, "matched_workstations": 1})}
    recent_cutoff = datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)

    headers = {"apiKey": api_key} if api_key else {}
    seen: dict[str, dict] = {}
    tools_queried = 0
    errors: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=40.0, headers=headers) as client:
            for tool, versions in sorted(inventory.items()):
                product = CPE_ALIASES.get(tool, _norm(tool))
                tools_queried += 1
                try:
                    cves = await _fetch_tool(client, product)
                except Exception as e:
                    errors.append(f"{tool}: {e.__class__.__name__}")
                    log.warning("nvd fetch failed for %s: %s", tool, e)
                    await asyncio.sleep(2)
                    continue
                for cve in cves:
                    matched_ids: set[str] = set()
                    matched_versions: set[str] = set()
                    ranges: list[str] = []
                    for cfg in cve.get("configurations") or []:
                        for node in cfg.get("nodes") or []:
                            for m in node.get("cpeMatch") or []:
                                prod, _ = _cpe_parts(m.get("criteria", ""))
                                if _norm(prod) != product:
                                    continue
                                rt = _range_text(m)
                                if rt not in ranges:
                                    ranges.append(rt)
                                for ver, ws_ids in versions.items():
                                    pv = _parse_ver(ver)
                                    if pv is not None and _match_vulnerable(m, pv):
                                        matched_ids |= ws_ids
                                        matched_versions.add(ver)
                    published = cve.get("published") or ""
                    try:
                        pub_dt = datetime.fromisoformat(published).replace(tzinfo=timezone.utc)
                    except ValueError:
                        pub_dt = recent_cutoff
                    if not matched_ids and pub_dt < recent_cutoff:
                        continue
                    sev, score = _severity(cve)
                    cid = cve["id"]
                    doc = seen.get(cid) or {
                        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"nvd:{cid}")),
                        "cve_id": cid,
                        "severity": sev,
                        "cvss": score,
                        "published": pub_dt.isoformat(),
                        "last_modified": cve.get("lastModified"),
                        "summary": _description(cve)[:600],
                        "affected_tool": tool,
                        "affected_versions": [],
                        "affected_range": "; ".join(ranges[:4]),
                        "remediation": _remediation(tool),
                        "matched_workstations": 0,
                        "matched_workstation_ids": [],
                        "source": "nvd",
                        "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                        "last_synced": _now(),
                    }
                    ids = set(doc["matched_workstation_ids"]) | matched_ids
                    doc["matched_workstation_ids"] = sorted(ids)
                    doc["matched_workstations"] = len(ids)
                    doc["affected_versions"] = sorted(set(doc["affected_versions"]) | matched_versions)
                    seen[cid] = doc
                await asyncio.sleep(0.7)

        dispatched = 0
        for cid, doc in seen.items():
            await db.cves.update_one({"cve_id": cid}, {"$set": doc}, upsert=True)
        # Alert only on NEW critical/high fleet hits, capped so a first sync cannot flood plugins.
        new_hits = sorted(
            (d for cid, d in seen.items() if d["matched_workstations"] > 0
             and previous.get(cid, {}).get("matched_workstations", 0) == 0
             and d["severity"] in ("critical", "high")),
            key=lambda d: -d["cvss"],
        )
        if dispatch:
            for doc in new_hits[:MAX_DISPATCH]:
                await dispatch("cve.matched", {
                    "cve_id": doc["cve_id"], "severity": doc["severity"], "cvss": doc["cvss"],
                    "affected_tool": doc["affected_tool"], "affected_versions": doc["affected_versions"],
                    "matched_workstations": doc["matched_workstations"], "summary": doc["summary"],
                    "remediation": doc["remediation"], "url": doc["url"],
                })
                dispatched += 1
        stale = await db.cves.delete_many({"source": "nvd", "cve_id": {"$nin": list(seen.keys())}})
        result = {
            "tools_queried": tools_queried,
            "cves_stored": len(seen),
            "fleet_affected": sum(1 for d in seen.values() if d["matched_workstations"] > 0),
            "new_high_hits": len(new_hits),
            "alerts_dispatched": dispatched,
            "stale_removed": stale.deleted_count,
            "errors": errors[:10],
            "api_key_used": bool(api_key),
        }
        await db.meta.update_one({"key": "nvd_sync"}, {"$set": {
            "status": "ok", "finished_at": _now(), "result": result,
        }})
        log.info("nvd sync done: %s", result)
        return result
    except Exception as e:
        await db.meta.update_one({"key": "nvd_sync"}, {"$set": {
            "status": "error", "finished_at": _now(), "error": f"{e.__class__.__name__}: {e}"[:400],
        }})
        raise
