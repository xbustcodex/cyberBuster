"""Plugin executor — dispatches events and runs on-demand queries.

- `dispatch(event_kind, payload)` fans out to all enabled plugins subscribed to the event.
- `query(plugin_id, params)` runs a synchronous on-demand lookup (VirusTotal / Shodan).
- Every call is logged in `plugin_executions` with status + latency + response snippet.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .catalog import get_type
from .crypto import decrypt

log = logging.getLogger("secmaster.plugins")

EVENT_KINDS = [
    "cve.matched",
    "workstation.enrolled",
    "workstation.profile_switched",
    "manual.test",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_ge(a: str, b: str) -> bool:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    return order.get(a, 0) >= order.get(b, 0)


def _summarize_event(kind: str, payload: dict) -> str:
    if kind == "cve.matched":
        return f"[{payload.get('severity','?').upper()}] {payload.get('cve_id')} · {payload.get('affected_tool')} · {payload.get('matched_workstations',0)} host(s) exposed"
    if kind == "workstation.enrolled":
        return f"New workstation enrolled: {payload.get('hostname')} ({payload.get('os')})"
    if kind == "workstation.profile_switched":
        return f"{payload.get('hostname')} switched profile → {payload.get('profile')} (by {payload.get('by')})"
    if kind == "manual.test":
        return f"sec-master plugin test-fire · {payload.get('note','manual')}"
    return f"sec-master event: {kind}"


# ---------------- Dispatch handlers ----------------
async def _dispatch_webhook(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    headers = {"Content-Type": "application/json", "User-Agent": "sec-master/plugin"}
    if cfg.get("headers"):
        try:
            headers.update(json.loads(cfg["headers"]))
        except Exception:
            pass
    body = json.dumps({"event": kind, "at": _now(), "data": payload}).encode()
    hmac_secret = secrets_dec.get("hmac_secret")
    if hmac_secret:
        sig = hmac.new(hmac_secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-SecMaster-Signature"] = f"sha256={sig}"
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post(cfg["url"], content=body, headers=headers)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_slack(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    msg = {
        "text": f":shield: *sec-master* · {_summarize_event(kind, payload)}",
        "attachments": [{"color": _slack_color(kind, payload),
                         "fields": [{"title": k, "value": str(v)[:400], "short": True} for k, v in list(payload.items())[:8]]}],
    }
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post(secrets_dec["webhook_url"], json=msg)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


def _slack_color(kind: str, payload: dict) -> str:
    sev = payload.get("severity")
    return {"critical": "#db4b4b", "high": "#f7768e", "medium": "#e0af68", "low": "#9ece6a"}.get(sev, "#7aa2f7")


async def _dispatch_discord(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    body = {
        "username": cfg.get("username") or "sec-master",
        "content": _summarize_event(kind, payload),
        "embeds": [{"description": "```" + json.dumps(payload, indent=2)[:1500] + "```"}],
    }
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post(secrets_dec["webhook_url"], json=body)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_pagerduty(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    min_sev = cfg.get("min_severity") or "high"
    if kind == "cve.matched" and not _severity_ge(payload.get("severity", "low"), min_sev):
        return {"status": 0, "body_snippet": f"skipped: severity {payload.get('severity')} < {min_sev}"}
    body = {
        "routing_key": secrets_dec["routing_key"],
        "event_action": "trigger",
        "payload": {
            "summary": _summarize_event(kind, payload),
            "source": "sec-master",
            "severity": payload.get("severity", "warning"),
            "custom_details": payload,
        },
    }
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post("https://events.pagerduty.com/v2/enqueue", json=body)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_splunk(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    body = {"event": {"event": kind, "at": _now(), "data": payload},
            "sourcetype": cfg.get("sourcetype") or "sec_master:event"}
    if cfg.get("index"):
        body["index"] = cfg["index"]
    headers = {"Authorization": f"Splunk {secrets_dec['hec_token']}"}
    async with httpx.AsyncClient(timeout=8.0, verify=bool(cfg.get("verify_tls", True))) as c:
        r = await c.post(cfg["url"], json=body, headers=headers)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_elastic(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    url = f"{cfg['url'].rstrip('/')}/{cfg['index']}/_doc"
    headers = {"Authorization": f"ApiKey {secrets_dec['api_key']}"}
    body = {"@timestamp": _now(), "event.kind": kind, "sec_master": payload}
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post(url, json=body, headers=headers)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_misp(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    if kind != "cve.matched":
        return {"status": 0, "body_snippet": "MISP plugin only handles cve.matched events"}
    event_id = cfg.get("event_id")
    url = f"{cfg['url'].rstrip('/')}/attributes/add/{event_id}" if event_id else f"{cfg['url'].rstrip('/')}/events/add"
    headers = {"Authorization": secrets_dec["api_key"], "Accept": "application/json", "Content-Type": "application/json"}
    body = ({"value": payload.get("cve_id"), "type": "vulnerability", "category": "External analysis"}
            if event_id
            else {"Event": {"info": _summarize_event(kind, payload), "distribution": "0", "threat_level_id": "2", "analysis": "0"}})
    async with httpx.AsyncClient(timeout=8.0, verify=bool(cfg.get("verify_tls", True))) as c:
        r = await c.post(url, json=body, headers=headers)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


async def _dispatch_gotify(cfg: dict, secrets_dec: dict, kind: str, payload: dict) -> dict:
    url = f"{cfg['url'].rstrip('/')}/message?token={secrets_dec['app_token']}"
    try:
        priority = int(cfg.get("priority") or 5)
    except (TypeError, ValueError):
        priority = 5
    body = {"title": _summarize_event(kind, payload), "message": json.dumps(payload)[:2000], "priority": priority}
    async with httpx.AsyncClient(timeout=8.0) as c:
        r = await c.post(url, json=body)
        return {"status": r.status_code, "body_snippet": r.text[:240]}


DISPATCH_HANDLERS = {
    "webhook": _dispatch_webhook,
    "slack": _dispatch_slack,
    "discord": _dispatch_discord,
    "pagerduty": _dispatch_pagerduty,
    "splunk_hec": _dispatch_splunk,
    "elastic": _dispatch_elastic,
    "misp": _dispatch_misp,
    "gotify": _dispatch_gotify,
}


# ---------------- Query handlers ----------------
async def _query_virustotal(secrets_dec: dict, params: dict) -> dict:
    kind = params.get("kind")
    value = params.get("value")
    base = "https://www.virustotal.com/api/v3"
    if kind == "hash":
        url = f"{base}/files/{value}"
    elif kind == "ip":
        url = f"{base}/ip_addresses/{value}"
    elif kind == "domain":
        url = f"{base}/domains/{value}"
    else:
        return {"status": 400, "body_snippet": "unsupported kind"}
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(url, headers={"x-apikey": secrets_dec["api_key"]})
        return {"status": r.status_code, "body_snippet": r.text[:800]}


async def _query_shodan(secrets_dec: dict, params: dict) -> dict:
    ip = params.get("ip")
    url = f"https://api.shodan.io/shodan/host/{ip}?key={secrets_dec['api_key']}"
    async with httpx.AsyncClient(timeout=10.0) as c:
        r = await c.get(url)
        return {"status": r.status_code, "body_snippet": r.text[:800]}


QUERY_HANDLERS = {
    "virustotal": _query_virustotal,
    "shodan": _query_shodan,
}


# ---------------- Entry points ----------------
async def dispatch(db, event_kind: str, payload: dict, only_plugin_id: str | None = None) -> list[dict]:
    """Fan out an event to every enabled subscribed plugin."""
    query: dict[str, Any] = {"enabled": True}
    if only_plugin_id:
        query["id"] = only_plugin_id
    else:
        query["event_subscriptions"] = event_kind

    results: list[dict] = []
    async for plug in db.plugins.find(query):
        ptype = get_type(plug["type"])
        if not ptype or "dispatch" not in ptype.get("capabilities", []):
            continue
        handler = DISPATCH_HANDLERS.get(plug["type"])
        if not handler:
            continue
        cfg = plug.get("config", {}) or {}
        secrets_dec = {k: decrypt(v) for k, v in (plug.get("secrets_encrypted", {}) or {}).items()}
        started = time.monotonic()
        record = {
            "id": secrets.token_hex(8),
            "plugin_id": plug["id"],
            "plugin_name": plug.get("name"),
            "plugin_type": plug["type"],
            "event": event_kind,
            "at": _now(),
        }
        try:
            r = await handler(cfg, secrets_dec, event_kind, payload)
            record.update({
                "status": "ok" if 200 <= (r.get("status", 0) or 0) < 300 else "error",
                "http_status": r.get("status"),
                "response": r.get("body_snippet", ""),
                "latency_ms": int((time.monotonic() - started) * 1000),
            })
        except Exception as e:
            record.update({
                "status": "error", "http_status": 0,
                "response": f"exception: {e.__class__.__name__}: {e}"[:400],
                "latency_ms": int((time.monotonic() - started) * 1000),
            })
        await db.plugin_executions.insert_one(record)
        await db.plugins.update_one({"id": plug["id"]}, {"$set": {
            "last_run_at": record["at"],
            "last_run_status": record["status"],
            "last_run_http": record["http_status"],
        }, "$inc": {"execution_count": 1}})
        results.append({k: v for k, v in record.items() if k != "_id"})
    return results


async def query(db, plugin: dict, params: dict) -> dict:
    ptype = get_type(plugin["type"])
    if not ptype or "query" not in ptype.get("capabilities", []):
        return {"status": "error", "error": "plugin does not support on-demand queries"}
    handler = QUERY_HANDLERS.get(plugin["type"])
    if not handler:
        return {"status": "error", "error": "no query handler registered"}
    secrets_dec = {k: decrypt(v) for k, v in (plugin.get("secrets_encrypted", {}) or {}).items()}
    started = time.monotonic()
    record = {
        "id": secrets.token_hex(8),
        "plugin_id": plugin["id"],
        "plugin_name": plugin.get("name"),
        "plugin_type": plugin["type"],
        "event": "query",
        "at": _now(),
    }
    try:
        r = await handler(secrets_dec, params)
        record.update({
            "status": "ok" if 200 <= (r.get("status", 0) or 0) < 300 else "error",
            "http_status": r.get("status"),
            "response": r.get("body_snippet", ""),
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
    except Exception as e:
        record.update({
            "status": "error", "http_status": 0,
            "response": f"exception: {e.__class__.__name__}: {e}"[:400],
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
    await db.plugin_executions.insert_one(record)
    await db.plugins.update_one({"id": plugin["id"]}, {"$set": {
        "last_run_at": record["at"],
        "last_run_status": record["status"],
        "last_run_http": record["http_status"],
    }, "$inc": {"execution_count": 1}})
    return record
