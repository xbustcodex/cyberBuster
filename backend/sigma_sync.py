"""Sigma Rule Repo Sync — pull .yml/.yaml from a GitHub repo, extract hashes.

Accepts flexible input:
  - "SigmaHQ/sigma"                                  → owner/repo, root, default branch
  - "SigmaHQ/sigma/rules/threat-hunting"             → path
  - "https://github.com/SigmaHQ/sigma"               → full URL
  - "https://github.com/SigmaHQ/sigma/tree/master/rules/threat-hunting"

Public repos only (unauthenticated GitHub API, 60 req/hr per IP). File count
capped at 200 per sync to bound requests.
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

import sigma_parser

log = logging.getLogger("secmaster.sigma_sync")

GITHUB_API = "https://api.github.com"
MAX_FILES = 200


def parse_repo_url(source: str) -> dict[str, str]:
    s = (source or "").strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/([^/]+)(/(.*))?)?/?$", s)
    if m:
        owner, repo, branch, _, path = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        return {"owner": owner, "repo": repo, "ref": branch or "", "path": (path or "").strip("/")}
    parts = [p for p in s.split("/") if p]
    if len(parts) >= 2:
        return {"owner": parts[0], "repo": parts[1], "ref": "", "path": "/".join(parts[2:])}
    raise ValueError(f"Unrecognised repo source: {source!r}")


async def _list_yaml_files(client: httpx.AsyncClient, owner: str, repo: str, path: str, ref: str) -> list[dict]:
    out: list[dict] = []
    stack: list[str] = [path]
    while stack and len(out) < MAX_FILES:
        current = stack.pop()
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{current}"
        params = {"ref": ref} if ref else None
        r = await client.get(url, params=params, headers={"Accept": "application/vnd.github+json"})
        if r.status_code == 404:
            continue
        if r.status_code == 403:
            raise RuntimeError("github rate-limited (60/hr unauth); try again later")
        r.raise_for_status()
        items = r.json()
        if isinstance(items, dict):
            items = [items]
        for item in items:
            if item.get("type") == "dir":
                stack.append(item["path"])
            elif item.get("type") == "file" and item.get("name", "").lower().endswith((".yml", ".yaml")):
                out.append(item)
                if len(out) >= MAX_FILES:
                    break
    return out


async def _apply_hashes(db, hashes: list[dict], scope: str, source_name: str) -> dict:
    from server import _now  # local import to avoid cycles
    import secrets
    query: dict[str, Any] = {}
    if scope == "all-online":
        query["status"] = "online"
    targets = await db.workstations.find(query, {"id": 1, "hostname": 1, "suspicious_hashes": 1}).to_list(500)
    added_total = 0
    for ws in targets:
        existing = {h.get("hash") for h in (ws.get("suspicious_hashes") or [])}
        new_entries = []
        for entry in hashes:
            if entry["hash"] in existing:
                continue
            new_entries.append({
                "hash": entry["hash"],
                "note": f"sigma-sync[{source_name}]: {entry['source_rule']}"[:120],
                "added_at": _now(),
                "source": "sigma-sync",
            })
        if new_entries:
            await db.workstations.update_one(
                {"id": ws["id"]},
                {"$push": {"suspicious_hashes": {"$each": new_entries, "$position": 0}}},
            )
            await db.audit.insert_one({
                "id": secrets.token_hex(8), "workstation_id": ws["id"], "hostname": ws["hostname"],
                "kind": "cve_match",
                "message": f"Sigma repo sync '{source_name}' added {len(new_entries)} hash IOC(s)",
                "at": _now(), "meta": {"source": source_name},
            })
            added_total += len(new_entries)
    return {"targets": len(targets), "hashes_added": added_total}


async def sync_source(db, source: dict) -> dict:
    info = parse_repo_url(source["github_url"])
    async with httpx.AsyncClient(timeout=20.0) as client:
        files = await _list_yaml_files(client, info["owner"], info["repo"], info["path"], info["ref"])
        combined = ""
        for f in files:
            try:
                dl = await client.get(f["download_url"])
                if dl.status_code == 200:
                    combined += dl.text + "\n---\n"
            except Exception:
                continue

    rules = sigma_parser.parse_sigma(combined)
    flat = sigma_parser.flatten_hashes(rules)
    scope = source.get("scope") or "all-online"
    apply_result = await _apply_hashes(db, flat, scope, source.get("name") or f"{info['owner']}/{info['repo']}")
    return {
        "files_seen": len(files),
        "rules_parsed": len(rules),
        "unique_hashes": len(flat),
        **apply_result,
        "repo": f"{info['owner']}/{info['repo']}",
        "path": info["path"] or "/",
        "ref": info["ref"] or "default",
    }
