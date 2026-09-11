"""Security Master — Fleet Dashboard API."""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
import json
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, APIRouter, Depends, HTTPException, Response, Request, Query
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

from models import (
    RegisterRequest, LoginRequest, UserPublic,
    Workstation, HeartbeatPayload, ProfileSwitchRequest,
    EnrollTokenOut, EnrollGenerateRequest,
    CveRecord, SignedRelease, AuditEvent,
)
from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    set_auth_cookies, clear_auth_cookies, get_current_user,
    JWT_ALGORITHM,
)
import jwt as pyjwt
import seed as seedmod
import plugins as sm_plugins
from plugins.crypto import encrypt as sm_encrypt, mask as sm_mask
import sigma_parser
import sigma_sync
import marketplace
import scheduler as sm_scheduler
import nvd
import releases_sync
import fleet_status
import bootstrap
import asyncio
from fastapi import Response as FastResponse
from fastapi.responses import PlainTextResponse

INFRA_DIR = ROOT_DIR.parent / "infrastructure"
PROFILES = ("offense", "defense", "analyst")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s :: %(message)s")
log = logging.getLogger("secmaster")

# DB
mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

app = FastAPI(title="Security Master API", version="0.11.0-rc1")
api = APIRouter(prefix="/api")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _client_ip(request: Request) -> Optional[str]:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _dashboard_url(request: Request) -> str:
    return (os.environ.get("FRONTEND_URL") or str(request.base_url)).rstrip("/")


# ============================================================
# AUTH
# ============================================================
@api.post("/auth/register")
async def register(body: RegisterRequest, response: Response):
    email = body.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(400, "Email already registered")
    user_id = secrets.token_hex(12)
    doc = {
        "id": user_id,
        "email": email,
        "name": body.name,
        "password_hash": hash_password(body.password),
        "role": "admin",
        "created_at": _now(),
    }
    await db.users.insert_one(doc)
    access = create_access_token(user_id, email)
    refresh = create_refresh_token(user_id)
    set_auth_cookies(response, access, refresh)
    doc.pop("password_hash", None); doc.pop("_id", None)
    return {"user": doc, "access_token": access}


@api.post("/auth/login")
async def login(body: LoginRequest, response: Response):
    email = body.email.lower()
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    access = create_access_token(user["id"], email)
    refresh = create_refresh_token(user["id"])
    set_auth_cookies(response, access, refresh)
    user.pop("password_hash", None); user.pop("_id", None)
    return {"user": user, "access_token": access}


@api.post("/auth/logout")
async def logout(response: Response, _user=Depends(get_current_user)):
    clear_auth_cookies(response)
    return {"ok": True}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


@api.post("/auth/refresh")
async def refresh_token(request: Request, response: Response):
    tok = request.cookies.get("refresh_token")
    if not tok:
        raise HTTPException(401, "Missing refresh token")
    try:
        payload = pyjwt.decode(tok, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])
    except pyjwt.InvalidTokenError:
        raise HTTPException(401, "Invalid refresh token")
    if payload.get("type") != "refresh":
        raise HTTPException(401, "Wrong token type")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "email": 1, "id": 1})
    if not user:
        raise HTTPException(401, "User not found")
    access = create_access_token(user["id"], user["email"])
    response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=3600 * 12, path="/")
    return {"access_token": access}


# ============================================================
# FLEET / WORKSTATIONS
# ============================================================
@api.get("/workstations")
async def list_workstations(
    profile: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    _user=Depends(get_current_user),
):
    query: dict = {}
    if profile and profile != "all":
        query["profile"] = profile
    if status and status != "all":
        query["status"] = status
    if q:
        query["hostname"] = {"$regex": q, "$options": "i"}
    docs = await db.workstations.find(query, {"_id": 0}).sort("hostname", 1).to_list(500)
    return docs


@api.get("/workstations/{ws_id}")
async def get_workstation(ws_id: str, _user=Depends(get_current_user)):
    ws = await db.workstations.find_one({"id": ws_id}, {"_id": 0})
    if not ws:
        raise HTTPException(404, "Workstation not found")
    audit = await db.audit.find({"workstation_id": ws_id}, {"_id": 0}).sort("at", -1).to_list(50)
    return {"workstation": ws, "audit": audit}


@api.post("/workstations/{ws_id}/switch-profile")
async def switch_profile(ws_id: str, body: ProfileSwitchRequest, user=Depends(get_current_user)):
    ws = await db.workstations.find_one({"id": ws_id})
    if not ws:
        raise HTTPException(404, "Workstation not found")
    previous = ws["profile"]
    if ws.get("demo"):
        await db.workstations.update_one({"id": ws_id}, {"$set": {"profile": body.profile, "status": "online"}})
        message = f"Profile switched to {body.profile} by {user['email']} (demo host — applied instantly)"
    else:
        await db.workstations.update_one({"id": ws_id}, {"$set": {
            "desired_profile": body.profile,
            "desired_profile_requested_at": _now(),
            "desired_profile_requested_by": user["email"],
            "status": "drift" if body.profile != previous else ws.get("status", "online"),
        }})
        message = f"Profile switch to {body.profile} requested by {user['email']} — agent applies on next heartbeat"
    await db.audit.insert_one({
        "id": secrets.token_hex(8),
        "workstation_id": ws_id,
        "hostname": ws["hostname"],
        "kind": "profile_switch",
        "message": message,
        "at": _now(),
        "meta": {"by": user["email"], "previous": previous, "requested": body.profile},
    })
    await sm_plugins.dispatch(db, "workstation.profile_switched", {
        "hostname": ws["hostname"], "workstation_id": ws_id,
        "profile": body.profile, "previous": previous, "by": user["email"],
        "pending": not ws.get("demo"),
    })
    return {"ok": True, "profile": body.profile, "pending": not ws.get("demo"), "message": message}


@api.delete("/workstations/{ws_id}")
async def delete_workstation(ws_id: str, _user=Depends(get_current_user)):
    res = await db.workstations.delete_one({"id": ws_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Workstation not found")
    await db.audit.delete_many({"workstation_id": ws_id})
    await db.ioc_lookups.delete_many({"workstation_id": ws_id})
    return {"ok": True}


# ============================================================
# DEMO DATA — labelled sample fleet, one-click purge
# ============================================================
async def _demo_counts() -> dict:
    return {
        "workstations": await db.workstations.count_documents({"demo": True}),
        "cves": await db.cves.count_documents({"demo": True}),
        "releases": await db.releases.count_documents({"demo": True}),
        "purged": bool(await db.meta.find_one({"key": "demo_purged"})),
    }


@api.get("/demo-data/status")
async def demo_status(_user=Depends(get_current_user)):
    return await _demo_counts()


@api.delete("/demo-data")
async def purge_demo_data(user=Depends(get_current_user)):
    ids = [w["id"] async for w in db.workstations.find({"demo": True}, {"id": 1})]
    r_ws = await db.workstations.delete_many({"demo": True})
    r_cve = await db.cves.delete_many({"demo": True})
    r_rel = await db.releases.delete_many({"demo": True})
    r_audit = await db.audit.delete_many({"$or": [{"demo": True}, {"workstation_id": {"$in": ids}}]})
    await db.ioc_lookups.delete_many({"workstation_id": {"$in": ids}})
    await db.meta.update_one({"key": "demo_purged"}, {"$set": {"at": _now(), "by": user["email"]}}, upsert=True)
    await db.cves.update_many({"source": "nvd", "matched_workstation_ids": {"$in": ids}},
                              {"$pull": {"matched_workstation_ids": {"$in": ids}}})
    async for c in db.cves.find({"source": "nvd"}, {"_id": 0, "cve_id": 1, "matched_workstation_ids": 1}):
        await db.cves.update_one({"cve_id": c["cve_id"]}, {"$set": {"matched_workstations": len(c.get("matched_workstation_ids") or [])}})
    log.info("demo data purged by %s", user["email"])
    return {"ok": True, "workstations": r_ws.deleted_count, "cves": r_cve.deleted_count,
            "releases": r_rel.deleted_count, "audit": r_audit.deleted_count}


# ============================================================
# ENROLLMENT
# ============================================================
@api.post("/enroll/generate", response_model=EnrollTokenOut)
async def generate_enroll_token(body: EnrollGenerateRequest, request: Request, _user=Depends(get_current_user)):
    token = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    await db.enroll_tokens.insert_one({
        "token": token,
        "hostname": body.hostname,
        "os": body.os,
        "expires_at": expires,
        "used": False,
    })
    backend = _dashboard_url(request)
    bash_cmd = (
        f'curl -fsSL {backend}/api/agent/bootstrap.sh | '
        f'ENROLL_TOKEN="{token}" SM_HOSTNAME="{body.hostname}" bash'
    )
    ps_cmd = (
        f'$env:ENROLL_TOKEN="{token}"; $env:SM_HOSTNAME="{body.hostname}"; '
        f'iwr {backend}/api/agent/bootstrap.ps1 -UseB | iex'
    )
    return EnrollTokenOut(
        token=token, hostname=body.hostname, os=body.os,
        expires_at=expires, bash_command=bash_cmd, powershell_command=ps_cmd,
    )


# ---------- Agent artifacts (public: fetched by hosts before they have a token) ----------
@api.get("/agent/bootstrap.sh", response_class=PlainTextResponse)
async def agent_bootstrap_sh(request: Request):
    return bootstrap.render(bootstrap.BASH, _dashboard_url(request))


@api.get("/agent/bootstrap.ps1", response_class=PlainTextResponse)
async def agent_bootstrap_ps1(request: Request):
    return bootstrap.render(bootstrap.POWERSHELL, _dashboard_url(request))


@api.get("/agent/agent.py", response_class=PlainTextResponse)
async def agent_source():
    return (INFRA_DIR / "agent" / "agent.py").read_text()


@api.get("/agent/SecurityMaster.psm1", response_class=PlainTextResponse)
async def agent_psm1():
    return (INFRA_DIR / "windows" / "SecurityMaster.psm1").read_text()


@api.get("/agent/sec-master", response_class=PlainTextResponse)
async def cli_source():
    return (INFRA_DIR / "cli" / "sec-master").read_text()


@api.post("/agent/enroll")
async def agent_enroll(request: Request):
    body = await request.json()
    token = body.get("token")
    if not token:
        raise HTTPException(400, "Missing token")
    tok = await db.enroll_tokens.find_one({"token": token})
    if not tok:
        raise HTTPException(401, "Invalid enroll token")
    if tok.get("used"):
        raise HTTPException(401, "Enroll token already used")
    if datetime.fromisoformat(tok["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(401, "Enroll token expired")
    ws_id = secrets.token_hex(12)
    agent_token = secrets.token_urlsafe(32)
    profile = body.get("profile") if body.get("profile") in PROFILES else "analyst"
    ws = {
        "id": ws_id,
        "hostname": body.get("hostname") or tok["hostname"],
        "os": tok["os"],
        "profile": profile,
        "desired_profile": None,
        "agent_version": body.get("agent_version", "0.1.0"),
        "flake_hash": body.get("flake_hash"),
        "dsc_hash": body.get("dsc_hash"),
        "os_release": body.get("os_release"),
        "tools": body.get("tools", []),
        "tags": [tok["os"], profile],
        "enrolled_at": _now(),
        "last_heartbeat": _now(),
        "status": "online",
        "ip_address": _client_ip(request),
        "local_ip": body.get("local_ip"),
        "agent_token": agent_token,
    }
    await db.workstations.insert_one(ws)
    await db.enroll_tokens.update_one({"token": token}, {"$set": {"used": True, "workstation_id": ws_id}})
    await db.audit.insert_one({
        "id": secrets.token_hex(8), "workstation_id": ws_id, "hostname": ws["hostname"],
        "kind": "enroll", "message": "Workstation enrolled", "at": _now(), "meta": {},
    })
    await sm_plugins.dispatch(db, "workstation.enrolled", {
        "hostname": ws["hostname"], "workstation_id": ws_id, "os": ws["os"], "profile": ws["profile"],
    })
    # Auto-enrich on enroll (fire-and-forget): if any query provider is enabled,
    # scan the workstation IP + any watchlist hashes right away.
    if ws.get("ip_address"):
        vt = await _find_enabled_query_plugin("virustotal")
        sh = await _find_enabled_query_plugin("shodan")
        if vt or sh:
            asyncio.create_task(_auto_enrich(ws))
    return {"workstation_id": ws_id, "agent_token": agent_token}


async def _auto_enrich(ws: dict) -> None:
    try:
        await _run_ioc_for_workstation(ws)
        await db.audit.insert_one({
            "id": secrets.token_hex(8),
            "workstation_id": ws["id"],
            "hostname": ws["hostname"],
            "kind": "cve_match",
            "message": "Auto-enrichment triggered on enroll",
            "at": _now(),
            "meta": {"trigger": "auto"},
        })
    except Exception as e:
        log.warning("auto-enrich failed for %s: %s", ws.get("hostname"), e)


@api.post("/agent/heartbeat")
async def agent_heartbeat(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing agent bearer token")
    token = auth[7:]
    ws = await db.workstations.find_one({"agent_token": token})
    if not ws:
        raise HTTPException(401, "Invalid agent token")
    body = await request.json()
    updates = {"last_heartbeat": _now()}
    for field in ("agent_version", "flake_hash", "dsc_hash", "tools", "local_ip", "os_release"):
        if field in body and body[field] is not None:
            updates[field] = body[field]
    reported = body.get("profile") if body.get("profile") in PROFILES else ws.get("profile")
    updates["profile"] = reported
    updates["ip_address"] = body.get("ip_address") or _client_ip(request) or ws.get("ip_address")
    desired = ws.get("desired_profile")
    updates["status"] = "drift" if desired and desired != reported else "online"
    if body.get("apply_error"):
        updates["last_apply_error"] = {"message": str(body["apply_error"])[:300], "at": _now()}
    elif ws.get("last_apply_error") and reported == desired:
        updates["last_apply_error"] = None

    events = []
    if reported != ws.get("profile"):
        events.append({"kind": "profile_switch",
                       "message": f"Agent reported profile {reported} (was {ws.get('profile')})"
                                  + (" — requested switch applied" if reported == desired else ""),
                       "meta": {"previous": ws.get("profile"), "applied": reported == desired}})
    old_tools = sorted((t.get("name"), t.get("version")) for t in ws.get("tools") or [] if isinstance(t, dict))
    new_tools = sorted((t.get("name"), t.get("version")) for t in updates.get("tools", ws.get("tools") or []) if isinstance(t, dict))
    if "tools" in updates and old_tools != new_tools:
        added = len(set(new_tools) - set(old_tools)); removed = len(set(old_tools) - set(new_tools))
        events.append({"kind": "tool_update", "message": f"Tool inventory changed (+{added} / -{removed})",
                       "meta": {"added": added, "removed": removed, "total": len(new_tools)}})
    if ws.get("status") == "offline":
        events.append({"kind": "heartbeat", "message": "Agent back online", "meta": {}})
    if body.get("apply_error") and (ws.get("last_apply_error") or {}).get("message") != str(body["apply_error"])[:300]:
        events.append({"kind": "profile_switch", "message": f"Agent failed to apply {desired}: {str(body['apply_error'])[:160]}",
                       "meta": {"error": True}})

    await db.workstations.update_one({"id": ws["id"]}, {"$set": updates})
    for ev in events:
        await db.audit.insert_one({"id": secrets.token_hex(8), "workstation_id": ws["id"], "hostname": ws["hostname"],
                                   "at": _now(), **ev})
    return {"ok": True, "next_check_in_seconds": 60, "desired_profile": desired, "status": updates["status"]}


# ============================================================
# CVE
# ============================================================
@api.get("/cves")
async def list_cves(severity: Optional[str] = None, _user=Depends(get_current_user)):
    query: dict = {}
    if severity and severity != "all":
        query["severity"] = severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    docs = await db.cves.find(query, {"_id": 0}).to_list(500)
    docs.sort(key=lambda x: (order.get(x.get("severity", "low"), 9), -x.get("cvss", 0)))
    return docs


@api.post("/cves/rescan")
async def rescan_cves(_user=Depends(get_current_user)):
    workstations = await db.workstations.find({}, {"_id": 0}).to_list(1000)
    updated = 0
    dispatched = 0
    async for cve in db.cves.find({}):
        matched = 0
        for ws in workstations:
            for t in ws.get("tools", []):
                if t.get("name") == cve.get("affected_tool") and t.get("version") in cve.get("affected_versions", []):
                    matched += 1
                    break
        prev = cve.get("matched_workstations", 0)
        await db.cves.update_one({"_id": cve["_id"]}, {"$set": {"matched_workstations": matched}})
        updated += 1
        if matched > 0 and matched != prev:
            await sm_plugins.dispatch(db, "cve.matched", {
                "cve_id": cve.get("cve_id"), "severity": cve.get("severity"),
                "cvss": cve.get("cvss"), "affected_tool": cve.get("affected_tool"),
                "affected_versions": cve.get("affected_versions", []),
                "matched_workstations": matched, "summary": cve.get("summary"),
                "remediation": cve.get("remediation"),
            })
            dispatched += 1
    return {"ok": True, "updated": updated, "dispatched": dispatched}


async def _dispatch_event(kind: str, payload: dict):
    return await sm_plugins.dispatch(db, kind, payload)


async def _nvd_sync_job() -> dict:
    return await nvd.sync(db, _dispatch_event)


@api.post("/cves/sync")
async def sync_cves(_user=Depends(get_current_user)):
    state = await db.meta.find_one({"key": "nvd_sync"}, {"_id": 0})
    if state and state.get("status") == "running":
        return {"ok": True, "started": False, "reason": "sync already running"}
    asyncio.create_task(_nvd_sync_job())
    return {"ok": True, "started": True}


@api.get("/cves/sync-status")
async def cve_sync_status(_user=Depends(get_current_user)):
    state = await db.meta.find_one({"key": "nvd_sync"}, {"_id": 0}) or {"status": "never"}
    tools = set()
    async for ws in db.workstations.find({}, {"_id": 0, "tools": 1}):
        tools.update(t.get("name") for t in ws.get("tools") or [] if isinstance(t, dict) and t.get("name"))
    state["fleet_tools"] = sorted(tools)
    state["api_key_configured"] = bool(os.environ.get("NVD_API_KEY"))
    return state


# ============================================================
# RELEASES
# ============================================================
@api.get("/releases")
async def list_releases(_user=Depends(get_current_user)):
    docs = await db.releases.find({}, {"_id": 0}).sort("published_at", -1).to_list(200)
    return docs


@api.get("/releases/status")
async def releases_status(_user=Depends(get_current_user)):
    state = await db.meta.find_one({"key": "releases_sync"}, {"_id": 0}) or {"status": "never"}
    state["repo"] = releases_sync.repo_name()
    return state


@api.post("/releases/sync")
async def sync_releases_now(_user=Depends(get_current_user)):
    try:
        result = await releases_sync.sync_releases(db)
    except Exception as e:
        raise HTTPException(502, f"GitHub sync failed: {e}")
    return {"ok": True, **result}


# ============================================================
# STATS
# ============================================================
@api.get("/stats/overview")
async def stats_overview(_user=Depends(get_current_user)):
    workstations = await db.workstations.find({}, {"_id": 0}).to_list(1000)
    cves = await db.cves.find({}, {"_id": 0}).to_list(1000)
    by_profile = {"offense": 0, "defense": 0, "analyst": 0}
    by_os = {"nixos": 0, "windows": 0}
    by_status = {"online": 0, "drift": 0, "offline": 0}
    for w in workstations:
        by_profile[w.get("profile", "analyst")] = by_profile.get(w.get("profile", "analyst"), 0) + 1
        by_os[w.get("os", "nixos")] = by_os.get(w.get("os", "nixos"), 0) + 1
        by_status[w.get("status", "online")] = by_status.get(w.get("status", "online"), 0) + 1
    cve_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in cves:
        s = c.get("severity", "low")
        cve_sev[s] = cve_sev.get(s, 0) + 1
    latest_release = await db.releases.find_one({}, {"_id": 0}, sort=[("published_at", -1)])
    return {
        "fleet_total": len(workstations),
        "real_total": sum(1 for w in workstations if not w.get("demo")),
        "by_profile": by_profile,
        "by_os": by_os,
        "by_status": by_status,
        "cve_total": len(cves),
        "cve_by_severity": cve_sev,
        "latest_release": latest_release,
        "demo": await _demo_counts(),
    }


# ============================================================
# AUDIT
# ============================================================
@api.get("/audit")
async def list_audit(limit: int = Query(100, le=500), _user=Depends(get_current_user)):
    docs = await db.audit.find({}, {"_id": 0}).sort("at", -1).to_list(limit)
    return docs


# ============================================================
# PLUGINS — full integration system
# ============================================================
@api.get("/plugins/catalog")
async def plugin_catalog(_user=Depends(get_current_user)):
    return sm_plugins.CATALOG


@api.get("/plugins/events")
async def plugin_events(_user=Depends(get_current_user)):
    return {"event_kinds": sm_plugins.EVENT_KINDS}


def _serialize_plugin(p: dict) -> dict:
    secrets_enc = p.get("secrets_encrypted", {}) or {}
    out = {k: v for k, v in p.items() if k not in ("_id", "secrets_encrypted")}
    ptype = sm_plugins.get_type(p["type"])
    schema = ptype.get("secrets_schema", []) if ptype else []
    out["secrets_masked"] = {}
    for f in schema:
        raw = secrets_enc.get(f["key"], "")
        out["secrets_masked"][f["key"]] = sm_mask(sm_plugins.decrypt(raw)) if raw else ""
    return out


@api.get("/plugins")
async def list_plugins(_user=Depends(get_current_user)):
    docs = await db.plugins.find({}).sort("created_at", -1).to_list(200)
    return [_serialize_plugin(d) for d in docs]


@api.post("/plugins")
async def create_plugin(request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    kind = body.get("type")
    ptype = sm_plugins.get_type(kind)
    if not ptype:
        raise HTTPException(400, f"Unknown plugin type: {kind}")

    subs = body.get("event_subscriptions") or []
    for s in subs:
        if s not in ptype.get("supported_events", []):
            raise HTTPException(400, f"Event {s} not supported by {kind}")

    secrets_in = body.get("secrets") or {}
    for f in ptype.get("secrets_schema", []):
        if f.get("required") and not secrets_in.get(f["key"]):
            raise HTTPException(400, f"Missing required secret: {f['key']}")
    secrets_enc = {k: sm_encrypt(v) for k, v in secrets_in.items() if v}

    plug_id = secrets.token_hex(10)
    doc = {
        "id": plug_id,
        "type": kind,
        "name": body.get("name") or ptype["display_name"],
        "enabled": bool(body.get("enabled", True)),
        "config": body.get("config") or {},
        "secrets_encrypted": secrets_enc,
        "event_subscriptions": subs,
        "created_at": _now(),
        "updated_at": _now(),
        "execution_count": 0,
        "last_run_at": None,
        "last_run_status": None,
    }
    await db.plugins.insert_one(doc)
    return _serialize_plugin(doc)


@api.patch("/plugins/{plug_id}")
async def update_plugin(plug_id: str, request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    plug = await db.plugins.find_one({"id": plug_id})
    if not plug:
        raise HTTPException(404, "Plugin not found")
    ptype = sm_plugins.get_type(plug["type"])

    updates: dict = {"updated_at": _now()}
    if "name" in body: updates["name"] = body["name"]
    if "enabled" in body: updates["enabled"] = bool(body["enabled"])
    if "config" in body: updates["config"] = body["config"] or {}
    if "event_subscriptions" in body:
        subs = body["event_subscriptions"] or []
        for s in subs:
            if s not in ptype.get("supported_events", []):
                raise HTTPException(400, f"Event {s} not supported by {plug['type']}")
        updates["event_subscriptions"] = subs
    if "secrets" in body and body["secrets"]:
        secrets_enc = plug.get("secrets_encrypted", {}) or {}
        for k, v in body["secrets"].items():
            if v:
                secrets_enc[k] = sm_encrypt(v)
        updates["secrets_encrypted"] = secrets_enc
    await db.plugins.update_one({"id": plug_id}, {"$set": updates})
    new_doc = await db.plugins.find_one({"id": plug_id})
    return _serialize_plugin(new_doc)


@api.delete("/plugins/{plug_id}")
async def delete_plugin(plug_id: str, _user=Depends(get_current_user)):
    res = await db.plugins.delete_one({"id": plug_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Plugin not found")
    await db.plugin_executions.delete_many({"plugin_id": plug_id})
    return {"ok": True}


@api.post("/plugins/{plug_id}/test")
async def test_plugin(plug_id: str, request: Request, user=Depends(get_current_user)):
    plug = await db.plugins.find_one({"id": plug_id})
    if not plug:
        raise HTTPException(404, "Plugin not found")
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    payload = {
        "note": body.get("note", "manual test-fire from dashboard"),
        "by": user.get("email"),
        "severity": "high", "cve_id": "CVE-TEST-0001",
        "affected_tool": "sec-master-plugin", "matched_workstations": 1,
    }
    results = await sm_plugins.dispatch(db, "manual.test", payload, only_plugin_id=plug_id)
    return {"ok": True, "results": results}


@api.post("/plugins/{plug_id}/query")
async def query_plugin(plug_id: str, request: Request, _user=Depends(get_current_user)):
    plug = await db.plugins.find_one({"id": plug_id})
    if not plug:
        raise HTTPException(404, "Plugin not found")
    params = await request.json()
    result = await sm_plugins.query(db, plug, params)
    return result


@api.get("/plugins/{plug_id}/executions")
async def plugin_executions(plug_id: str, limit: int = Query(50, le=200), _user=Depends(get_current_user)):
    docs = await db.plugin_executions.find({"plugin_id": plug_id}, {"_id": 0}).sort("at", -1).to_list(limit)
    return docs


# ============================================================
# PLUGIN TEMPLATES — save named configs, one-click reuse
# ============================================================
def _serialize_template(t: dict) -> dict:
    out = {k: v for k, v in t.items() if k not in ("_id", "secrets_encrypted")}
    ptype = sm_plugins.get_type(t["type"])
    schema = ptype.get("secrets_schema", []) if ptype else []
    secrets_enc = t.get("secrets_encrypted", {}) or {}
    out["has_secrets"] = bool(secrets_enc)
    out["secrets_masked"] = {}
    for f in schema:
        raw = secrets_enc.get(f["key"], "")
        out["secrets_masked"][f["key"]] = sm_mask(sm_plugins.decrypt(raw)) if raw else ""
    return out


@api.get("/plugin-templates")
async def list_templates(_user=Depends(get_current_user)):
    docs = await db.plugin_templates.find({}).sort([("shared", -1), ("created_at", -1)]).to_list(200)
    return [_serialize_template(t) for t in docs]


@api.post("/plugins/{plug_id}/save-as-template")
async def save_as_template(plug_id: str, request: Request, user=Depends(get_current_user)):
    body = await request.json()
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(400, "Template name required")
    include_secrets = bool(body.get("include_secrets", False))
    plug = await db.plugins.find_one({"id": plug_id})
    if not plug:
        raise HTTPException(404, "Plugin not found")
    if await db.plugin_templates.find_one({"name": name}):
        raise HTTPException(400, f"Template '{name}' already exists")
    doc = {
        "id": secrets.token_hex(10),
        "name": name,
        "type": plug["type"],
        "config": plug.get("config", {}),
        "event_subscriptions": plug.get("event_subscriptions", []),
        "secrets_encrypted": plug.get("secrets_encrypted", {}) if include_secrets else {},
        "created_by": user.get("email"),
        "created_at": _now(),
        "shared": bool(body.get("shared", False)),
    }
    await db.plugin_templates.insert_one(doc)
    return _serialize_template(doc)


@api.patch("/plugin-templates/{tpl_id}")
async def patch_template(tpl_id: str, request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    updates: dict = {}
    if "name" in body:
        name = (body["name"] or "").strip()
        if not name:
            raise HTTPException(400, "Name cannot be empty")
        existing = await db.plugin_templates.find_one({"name": name, "id": {"$ne": tpl_id}})
        if existing:
            raise HTTPException(400, f"Another template already named '{name}'")
        updates["name"] = name
    if "shared" in body:
        updates["shared"] = bool(body["shared"])
    if not updates:
        raise HTTPException(400, "Nothing to update")
    res = await db.plugin_templates.update_one({"id": tpl_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "Template not found")
    doc = await db.plugin_templates.find_one({"id": tpl_id})
    return _serialize_template(doc)


@api.delete("/plugin-templates/{tpl_id}")
async def delete_template(tpl_id: str, _user=Depends(get_current_user)):
    res = await db.plugin_templates.delete_one({"id": tpl_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Template not found")
    return {"ok": True}


@api.post("/plugins/from-template/{tpl_id}")
async def install_from_template(tpl_id: str, request: Request, _user=Depends(get_current_user)):
    tpl = await db.plugin_templates.find_one({"id": tpl_id})
    if not tpl:
        raise HTTPException(404, "Template not found")
    ptype = sm_plugins.get_type(tpl["type"])
    if not ptype:
        raise HTTPException(400, "Template plugin type no longer available")
    body: dict = {}
    try: body = await request.json()
    except Exception: pass

    secrets_enc = dict(tpl.get("secrets_encrypted", {}) or {})
    for k, v in (body.get("secrets") or {}).items():
        if v:
            secrets_enc[k] = sm_encrypt(v)

    for f in ptype.get("secrets_schema", []):
        if f.get("required") and not secrets_enc.get(f["key"]):
            raise HTTPException(400, f"Missing required secret from template: {f['key']}")

    plug_id = secrets.token_hex(10)
    doc = {
        "id": plug_id,
        "type": tpl["type"],
        "name": (body.get("name") or f"{ptype['display_name']} (from {tpl['name']})"),
        "enabled": bool(body.get("enabled", True)),
        "config": {**(tpl.get("config") or {}), **(body.get("config_overrides") or {})},
        "secrets_encrypted": secrets_enc,
        "event_subscriptions": body.get("event_subscriptions") or tpl.get("event_subscriptions", []),
        "created_at": _now(),
        "updated_at": _now(),
        "execution_count": 0,
        "last_run_at": None,
        "last_run_status": None,
        "template_id": tpl_id,
    }
    await db.plugins.insert_one(doc)
    return _serialize_plugin(doc)


# ============================================================
# IOC LOOKUPS — VirusTotal + Shodan enrichment per workstation
# ============================================================
async def _find_enabled_query_plugin(kind: str) -> dict | None:
    return await db.plugins.find_one({"type": kind, "enabled": True})


def _summarize_vt(response: str) -> dict:
    try:
        parsed = json.loads(response)
        attr = (parsed.get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "country": attr.get("country"),
            "as_owner": attr.get("as_owner"),
        }
    except Exception:
        return {}


def _summarize_shodan(response: str) -> dict:
    try:
        parsed = json.loads(response)
        return {
            "org": parsed.get("org"),
            "isp": parsed.get("isp"),
            "country": parsed.get("country_name"),
            "os": parsed.get("os"),
            "ports": (parsed.get("ports") or [])[:20],
            "vulns": list((parsed.get("vulns") or {}).keys())[:20]
                     if isinstance(parsed.get("vulns"), dict)
                     else (parsed.get("vulns") or [])[:20],
            "tags": parsed.get("tags") or [],
            "hostnames": parsed.get("hostnames") or [],
        }
    except Exception:
        return {}


@api.get("/workstations/{ws_id}/ioc")
async def get_ioc(ws_id: str, _user=Depends(get_current_user)):
    ws = await db.workstations.find_one({"id": ws_id}, {"_id": 0})
    if not ws:
        raise HTTPException(404, "Workstation not found")
    history = await db.ioc_lookups.find({"workstation_id": ws_id}, {"_id": 0}).sort("at", -1).to_list(50)
    vt = await _find_enabled_query_plugin("virustotal")
    sh = await _find_enabled_query_plugin("shodan")
    return {
        "ip_address": ws.get("ip_address"),
        "suspicious_hashes": ws.get("suspicious_hashes", []),
        "history": history,
        "providers": {
            "virustotal": {"enabled": bool(vt), "plugin_id": vt["id"] if vt else None},
            "shodan": {"enabled": bool(sh), "plugin_id": sh["id"] if sh else None},
        },
    }


@api.post("/workstations/{ws_id}/ioc/hashes")
async def add_hash(ws_id: str, request: Request, _user=Depends(get_current_user)):
    ws = await db.workstations.find_one({"id": ws_id})
    if not ws:
        raise HTTPException(404, "Workstation not found")
    body = await request.json()
    h = (body.get("hash") or "").strip().lower()
    note = (body.get("note") or "").strip()
    if not h or len(h) not in (32, 40, 64):
        raise HTTPException(400, "Hash must be MD5/SHA1/SHA256")
    entry = {"hash": h, "note": note, "added_at": _now()}
    await db.workstations.update_one(
        {"id": ws_id},
        {"$pull": {"suspicious_hashes": {"hash": h}}},
    )
    await db.workstations.update_one(
        {"id": ws_id},
        {"$push": {"suspicious_hashes": {"$each": [entry], "$position": 0}}},
    )
    return {"ok": True, "entry": entry}


@api.delete("/workstations/{ws_id}/ioc/hashes/{hash_value}")
async def remove_hash(ws_id: str, hash_value: str, _user=Depends(get_current_user)):
    await db.workstations.update_one(
        {"id": ws_id},
        {"$pull": {"suspicious_hashes": {"hash": hash_value.lower()}}},
    )
    await db.ioc_lookups.delete_many({"workstation_id": ws_id, "target_value": hash_value.lower()})
    return {"ok": True}


@api.post("/workstations/{ws_id}/ioc/lookup")
async def run_ioc_lookup(ws_id: str, request: Request, _user=Depends(get_current_user)):
    ws = await db.workstations.find_one({"id": ws_id}, {"_id": 0})
    if not ws:
        raise HTTPException(404, "Workstation not found")
    body: dict = {}
    try: body = await request.json()
    except Exception: pass

    targets = body.get("targets")
    result = await _run_ioc_for_workstation(ws, explicit_targets=targets)
    return {"ok": True, **result}


async def _run_ioc_for_workstation(ws: dict, explicit_targets: list | None = None) -> dict:
    """Shared IOC dispatch used by single-ws endpoint, bulk sweep, and auto-enrich."""
    targets = explicit_targets
    if not targets:
        targets = []
        if ws.get("ip_address"):
            targets.append({"type": "ip", "value": ws["ip_address"]})
        for h in ws.get("suspicious_hashes", []):
            targets.append({"type": "hash", "value": h["hash"]})

    vt = await _find_enabled_query_plugin("virustotal")
    sh = await _find_enabled_query_plugin("shodan")

    results = []
    for tgt in targets:
        ttype, tval = tgt.get("type"), tgt.get("value")
        if not (ttype and tval):
            continue

        if vt and ttype in ("ip", "hash", "domain"):
            vt_kind = "hash" if ttype == "hash" else ttype
            r = await sm_plugins.query(db, vt, {"kind": vt_kind, "value": tval})
            summary = _summarize_vt(r.get("response", "")) if r.get("status") == "ok" else {}
            rec = {
                "id": secrets.token_hex(8),
                "workstation_id": ws["id"],
                "hostname": ws.get("hostname"),
                "target_type": ttype, "target_value": tval,
                "provider": "virustotal",
                "status": r.get("status"), "http_status": r.get("http_status"),
                "summary": summary,
                "raw_snippet": (r.get("response") or "")[:600],
                "at": _now(),
            }
            await db.ioc_lookups.insert_one(rec)
            rec.pop("_id", None)
            results.append(rec)

        if sh and ttype == "ip":
            r = await sm_plugins.query(db, sh, {"ip": tval})
            summary = _summarize_shodan(r.get("response", "")) if r.get("status") == "ok" else {}
            rec = {
                "id": secrets.token_hex(8),
                "workstation_id": ws["id"],
                "hostname": ws.get("hostname"),
                "target_type": ttype, "target_value": tval,
                "provider": "shodan",
                "status": r.get("status"), "http_status": r.get("http_status"),
                "summary": summary,
                "raw_snippet": (r.get("response") or "")[:600],
                "at": _now(),
            }
            await db.ioc_lookups.insert_one(rec)
            rec.pop("_id", None)
            results.append(rec)

    return {"count": len(results), "results": results,
            "providers_used": {"virustotal": bool(vt), "shodan": bool(sh)}}


@api.post("/ioc/bulk-sweep")
async def bulk_ioc_sweep(request: Request, user=Depends(get_current_user)):
    """Run IOC enrichment across every online workstation in one pass."""
    body: dict = {}
    try: body = await request.json()
    except Exception: pass
    scope = body.get("scope", "online")

    vt = await _find_enabled_query_plugin("virustotal")
    sh = await _find_enabled_query_plugin("shodan")
    if not vt and not sh:
        raise HTTPException(400, "No VirusTotal or Shodan plugin enabled")

    query: dict = {}
    if scope == "online":
        query["status"] = "online"
    workstations = await db.workstations.find(query, {"_id": 0}).to_list(200)

    per_host: list[dict] = []
    total = 0
    skipped = 0
    for ws in workstations:
        if not ws.get("ip_address"):
            skipped += 1
            continue
        r = await _run_ioc_for_workstation(ws)
        total += r["count"]
        per_host.append({
            "workstation_id": ws["id"],
            "hostname": ws["hostname"],
            "ip": ws.get("ip_address"),
            "lookups": r["count"],
        })
    await db.audit.insert_one({
        "id": secrets.token_hex(8),
        "workstation_id": "*",
        "hostname": "*",
        "kind": "cve_match",  # reuse existing enum
        "message": f"Bulk IOC sweep ({scope}) by {user['email']} — {total} lookups across {len(per_host)} host(s)",
        "at": _now(),
        "meta": {"by": user["email"], "scope": scope, "skipped": skipped},
    })
    return {"ok": True, "scope": scope, "hosts_swept": len(per_host), "skipped": skipped,
            "total_lookups": total, "per_host": per_host,
            "providers_used": {"virustotal": bool(vt), "shodan": bool(sh)}}


# ============================================================
# SIGMA RULE IMPORT — extract hashes → watchlists
# ============================================================
@api.post("/sigma/preview")
async def sigma_preview(request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    text = body.get("sigma_yaml") or ""
    rules = sigma_parser.parse_sigma(text)
    flat = sigma_parser.flatten_hashes(rules)
    return {"rules": rules, "unique_hashes": flat, "hash_count": len(flat)}


@api.post("/sigma/import")
async def sigma_import(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    text = body.get("sigma_yaml") or ""
    workstation_ids = body.get("workstation_ids") or []
    scope = body.get("scope")  # "all-online" | "all" | None

    rules = sigma_parser.parse_sigma(text)
    flat = sigma_parser.flatten_hashes(rules)
    if not flat:
        raise HTTPException(400, "No hashes extracted from Sigma input")

    query: dict = {}
    if scope == "all-online":
        query["status"] = "online"
    elif scope == "all":
        pass
    else:
        if not workstation_ids:
            raise HTTPException(400, "Provide workstation_ids or scope=all-online|all")
        query["id"] = {"$in": workstation_ids}

    targets = await db.workstations.find(query, {"id": 1, "hostname": 1, "suspicious_hashes": 1}).to_list(500)
    if not targets:
        raise HTTPException(400, "No matching workstations")

    added_per_ws = []
    for ws in targets:
        existing = {h.get("hash") for h in (ws.get("suspicious_hashes") or [])}
        new_entries = []
        for entry in flat:
            if entry["hash"] in existing:
                continue
            new_entries.append({
                "hash": entry["hash"],
                "note": f"sigma: {entry['source_rule']}"[:120],
                "added_at": _now(),
                "source": "sigma",
            })
        if new_entries:
            await db.workstations.update_one(
                {"id": ws["id"]},
                {"$push": {"suspicious_hashes": {"$each": new_entries, "$position": 0}}},
            )
            await db.audit.insert_one({
                "id": secrets.token_hex(8), "workstation_id": ws["id"], "hostname": ws["hostname"],
                "kind": "cve_match",
                "message": f"Sigma import: {len(new_entries)} hash IOC(s) added by {user['email']}",
                "at": _now(), "meta": {"rules": len(rules)},
            })
        added_per_ws.append({
            "workstation_id": ws["id"],
            "hostname": ws["hostname"],
            "added": len(new_entries),
        })

    return {
        "ok": True,
        "rules_parsed": len(rules),
        "unique_hashes": len(flat),
        "targets": len(targets),
        "per_workstation": added_per_ws,
    }


# ============================================================
# AUTOMATIONS — Scheduled bulk sweeps, Sigma repo sync, Marketplace subscriptions
# ============================================================
def _serialize_schedule(s: dict) -> dict:
    return {k: v for k, v in s.items() if k != "_id"}


@api.get("/schedules")
async def list_schedules(_user=Depends(get_current_user)):
    docs = await db.schedules.find({}).sort("created_at", -1).to_list(200)
    return [_serialize_schedule(d) for d in docs]


@api.post("/schedules")
async def create_schedule(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    scope = body.get("scope", "online")
    if scope not in ("online", "all"):
        raise HTTPException(400, "scope must be 'online' or 'all'")
    interval = int(body.get("interval_hours") or 24)
    if interval < 1 or interval > 24 * 30:
        raise HTTPException(400, "interval_hours must be between 1 and 720")
    doc = {
        "id": secrets.token_hex(10),
        "kind": "bulk_sweep",
        "name": body.get("name") or f"nightly {scope} sweep",
        "enabled": bool(body.get("enabled", True)),
        "interval_hours": interval,
        "scope": scope,
        "created_by": user.get("email"),
        "created_at": _now(),
        "last_run_at": None,
        "last_run_status": None,
    }
    await db.schedules.insert_one(doc)
    return _serialize_schedule(doc)


@api.patch("/schedules/{sched_id}")
async def patch_schedule(sched_id: str, request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    updates: dict = {}
    for k in ("name", "enabled", "scope"):
        if k in body:
            updates[k] = body[k]
    if "interval_hours" in body:
        v = int(body["interval_hours"])
        if v < 1 or v > 24 * 30:
            raise HTTPException(400, "interval_hours must be between 1 and 720")
        updates["interval_hours"] = v
    if not updates:
        raise HTTPException(400, "Nothing to update")
    res = await db.schedules.update_one({"id": sched_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "Schedule not found")
    doc = await db.schedules.find_one({"id": sched_id})
    return _serialize_schedule(doc)


@api.delete("/schedules/{sched_id}")
async def delete_schedule(sched_id: str, _user=Depends(get_current_user)):
    res = await db.schedules.delete_one({"id": sched_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Schedule not found")
    return {"ok": True}


async def _run_scheduled_bulk_sweep(job: dict) -> dict:
    scope = job.get("scope", "online")
    vt = await _find_enabled_query_plugin("virustotal")
    sh = await _find_enabled_query_plugin("shodan")
    if not vt and not sh:
        return {"skipped": True, "reason": "no query provider enabled"}
    query: dict = {}
    if scope == "online":
        query["status"] = "online"
    workstations = await db.workstations.find(query, {"_id": 0}).to_list(200)
    total, hosts = 0, 0
    for ws in workstations:
        if not ws.get("ip_address"):
            continue
        r = await _run_ioc_for_workstation(ws)
        total += r["count"]
        hosts += 1
    return {"scope": scope, "hosts_swept": hosts, "total_lookups": total}


async def _run_schedule(job: dict) -> dict:
    kind = job.get("kind", "bulk_sweep")
    if kind == "nvd_sync":
        return await _nvd_sync_job()
    if kind == "releases_sync":
        return await releases_sync.sync_releases(db)
    return await _run_scheduled_bulk_sweep(job)


@api.post("/schedules/{sched_id}/run-now")
async def run_schedule_now(sched_id: str, _user=Depends(get_current_user)):
    job = await db.schedules.find_one({"id": sched_id})
    if not job:
        raise HTTPException(404, "Schedule not found")
    try:
        result = await _run_schedule(job)
    except Exception as e:
        await db.schedules.update_one({"id": sched_id}, {"$set": {
            "last_run_at": _now(), "last_run_status": "error",
            "last_run_meta": {"error": f"{e.__class__.__name__}: {e}"[:400]},
        }})
        raise HTTPException(502, f"run failed: {e}")
    await db.schedules.update_one({"id": sched_id}, {"$set": {
        "last_run_at": _now(), "last_run_status": "ok", "last_run_meta": result,
    }})
    return {"ok": True, **result}


# ---------- Sigma sources ----------
@api.get("/sigma-sources")
async def list_sigma_sources(_user=Depends(get_current_user)):
    docs = await db.sigma_sources.find({}).sort("created_at", -1).to_list(200)
    return [_serialize_schedule(d) for d in docs]


@api.post("/sigma-sources")
async def create_sigma_source(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    github_url = (body.get("github_url") or "").strip()
    if not github_url:
        raise HTTPException(400, "github_url required")
    try:
        sigma_sync.parse_repo_url(github_url)
    except ValueError as e:
        raise HTTPException(400, str(e))
    scope = body.get("scope") or "all-online"
    if scope not in ("all-online", "all"):
        raise HTTPException(400, "scope must be 'all-online' or 'all'")
    interval = int(body.get("interval_hours") or 24)
    doc = {
        "id": secrets.token_hex(10),
        "name": body.get("name") or github_url.rstrip("/").split("/")[-1] or "sigma-source",
        "github_url": github_url,
        "scope": scope,
        "enabled": bool(body.get("enabled", True)),
        "interval_hours": interval,
        "created_by": user.get("email"),
        "created_at": _now(),
        "last_run_at": None,
        "last_run_status": None,
    }
    await db.sigma_sources.insert_one(doc)
    return _serialize_schedule(doc)


@api.patch("/sigma-sources/{src_id}")
async def patch_sigma_source(src_id: str, request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    updates: dict = {}
    for k in ("name", "enabled", "scope", "github_url"):
        if k in body:
            updates[k] = body[k]
    if "interval_hours" in body:
        updates["interval_hours"] = int(body["interval_hours"])
    if not updates:
        raise HTTPException(400, "Nothing to update")
    res = await db.sigma_sources.update_one({"id": src_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "Sigma source not found")
    doc = await db.sigma_sources.find_one({"id": src_id})
    return _serialize_schedule(doc)


@api.delete("/sigma-sources/{src_id}")
async def delete_sigma_source(src_id: str, _user=Depends(get_current_user)):
    res = await db.sigma_sources.delete_one({"id": src_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Sigma source not found")
    return {"ok": True}


@api.post("/sigma-sources/{src_id}/sync-now")
async def sync_sigma_source_now(src_id: str, _user=Depends(get_current_user)):
    src = await db.sigma_sources.find_one({"id": src_id})
    if not src:
        raise HTTPException(404, "Sigma source not found")
    try:
        result = await sigma_sync.sync_source(db, src)
    except Exception as e:
        await db.sigma_sources.update_one({"id": src_id}, {"$set": {
            "last_run_at": _now(), "last_run_status": "error",
            "last_run_meta": {"error": f"{e.__class__.__name__}: {e}"[:400]},
        }})
        raise HTTPException(502, f"sync failed: {e}")
    await db.sigma_sources.update_one({"id": src_id}, {"$set": {
        "last_run_at": _now(), "last_run_status": "ok", "last_run_meta": result,
    }})
    return {"ok": True, **result}


# ---------- Marketplace (own feed + subscriptions) ----------
@api.get("/marketplace/info")
async def marketplace_info(request: Request, _user=Depends(get_current_user)):
    cfg = await marketplace.get_or_create_config(db)
    base = str(request.base_url).rstrip("/")
    feed_url = f"{base}/api/marketplace/feed?fid={cfg['feed_id']}"
    return {
        "feed_id": cfg["feed_id"],
        "signing_key": cfg["signing_key"],
        "feed_url": feed_url,
        "created_at": cfg.get("created_at"),
        "rotated_at": cfg.get("rotated_at"),
    }


@api.post("/marketplace/rotate-key")
async def marketplace_rotate(_user=Depends(get_current_user)):
    cfg = await marketplace.rotate_signing_key(db)
    return {"ok": True, "signing_key": cfg["signing_key"]}


@api.get("/marketplace/feed")
async def marketplace_feed(fid: Optional[str] = None):
    """PUBLIC endpoint — served without auth so other dashboards can subscribe."""
    cfg = await marketplace.get_or_create_config(db)
    if fid and fid != cfg["feed_id"]:
        raise HTTPException(404, "unknown feed_id")
    body, sig = await marketplace.build_feed(db)
    body["_signature"] = sig  # inline for clients that can't read headers
    resp = FastResponse(
        content=json.dumps(body, sort_keys=True),
        media_type="application/json",
        headers={"X-SecMaster-Signature": sig, "Cache-Control": "public, max-age=60"},
    )
    return resp


@api.get("/marketplace/subscriptions")
async def list_subscriptions(_user=Depends(get_current_user)):
    docs = await db.marketplace_subscriptions.find({}).sort("created_at", -1).to_list(200)
    return [_serialize_schedule(d) for d in docs]


@api.post("/marketplace/subscriptions")
async def create_subscription(request: Request, user=Depends(get_current_user)):
    body = await request.json()
    feed_url = (body.get("feed_url") or "").strip()
    if not feed_url.startswith(("http://", "https://")):
        raise HTTPException(400, "feed_url must be an http(s) URL")
    doc = {
        "id": secrets.token_hex(10),
        "name": body.get("name") or "peer-feed",
        "feed_url": feed_url,
        "signing_key": body.get("signing_key") or None,
        "enabled": bool(body.get("enabled", True)),
        "interval_hours": int(body.get("interval_hours") or 24),
        "created_by": user.get("email"),
        "created_at": _now(),
        "last_run_at": None,
        "last_run_status": None,
    }
    await db.marketplace_subscriptions.insert_one(doc)
    return _serialize_schedule(doc)


@api.patch("/marketplace/subscriptions/{sub_id}")
async def patch_subscription(sub_id: str, request: Request, _user=Depends(get_current_user)):
    body = await request.json()
    updates: dict = {}
    for k in ("name", "enabled", "feed_url", "signing_key"):
        if k in body:
            updates[k] = body[k]
    if "interval_hours" in body:
        updates["interval_hours"] = int(body["interval_hours"])
    if not updates:
        raise HTTPException(400, "Nothing to update")
    res = await db.marketplace_subscriptions.update_one({"id": sub_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "Subscription not found")
    doc = await db.marketplace_subscriptions.find_one({"id": sub_id})
    return _serialize_schedule(doc)


@api.delete("/marketplace/subscriptions/{sub_id}")
async def delete_subscription(sub_id: str, _user=Depends(get_current_user)):
    res = await db.marketplace_subscriptions.delete_one({"id": sub_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Subscription not found")
    await db.plugin_templates.delete_many({"subscription_id": sub_id})
    return {"ok": True}


@api.post("/marketplace/subscriptions/{sub_id}/sync-now")
async def sync_subscription_now(sub_id: str, _user=Depends(get_current_user)):
    sub = await db.marketplace_subscriptions.find_one({"id": sub_id})
    if not sub:
        raise HTTPException(404, "Subscription not found")
    try:
        result = await marketplace.verify_and_import_subscription(db, sub)
    except Exception as e:
        await db.marketplace_subscriptions.update_one({"id": sub_id}, {"$set": {
            "last_run_at": _now(), "last_run_status": "error",
            "last_run_meta": {"error": f"{e.__class__.__name__}: {e}"[:400]},
        }})
        raise HTTPException(502, f"sync failed: {e}")
    await db.marketplace_subscriptions.update_one({"id": sub_id}, {"$set": {
        "last_run_at": _now(), "last_run_status": "ok", "last_run_meta": result,
    }})
    return {"ok": True, **result}


# ============================================================
# HEALTH
# ============================================================
@api.get("/")
async def root():
    return {"service": "security-master", "version": app.version}


@api.get("/health")
async def health():
    try:
        await db.command("ping")
        return {"status": "ok", "db": "up"}
    except Exception as e:
        return {"status": "degraded", "db": str(e)}


# ============================================================
# STARTUP: seed + indexes + admin
# ============================================================
@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.workstations.create_index("hostname")
    await db.workstations.create_index("agent_token")
    await db.enroll_tokens.create_index("token", unique=True)
    await db.cves.create_index("cve_id", unique=True)
    await db.plugins.create_index("id", unique=True)
    await db.plugin_executions.create_index("plugin_id")
    await db.plugin_templates.create_index("name", unique=True)
    await db.ioc_lookups.create_index([("workstation_id", 1), ("at", -1)])
    await db.schedules.create_index("id", unique=True)
    await db.sigma_sources.create_index("id", unique=True)
    await db.marketplace_subscriptions.create_index("id", unique=True)
    await db.meta.create_index("key", unique=True)
    await db.cves.create_index("source")
    # A sync interrupted by a restart must not stay "running" forever.
    await db.meta.update_many({"key": {"$in": ["nvd_sync", "releases_sync"]}, "status": "running"},
                              {"$set": {"status": "interrupted", "finished_at": _now()}})

    admin_email = os.environ.get("ADMIN_EMAIL", "admin@secmaster.io").lower()
    admin_pw = os.environ.get("ADMIN_PASSWORD", "admin1234")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "id": secrets.token_hex(12), "email": admin_email, "name": "Admin",
            "password_hash": hash_password(admin_pw), "role": "admin", "created_at": _now(),
        })
        log.info("Seeded admin user: %s", admin_email)
    elif not verify_password(admin_pw, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_pw)}})
        log.info("Updated admin password from env")

    if not await db.meta.find_one({"key": "demo_purged"}) and await db.workstations.count_documents({}) == 0:
        workstations = seedmod.build_workstations()
        await db.workstations.insert_many(workstations)
        cves = seedmod.build_cves(workstations)
        await db.cves.insert_many(cves)
        releases = seedmod.build_releases()
        await db.releases.insert_many(releases)
        audit = seedmod.build_audit(workstations)
        if audit:
            await db.audit.insert_many(audit)
        log.info("Seeded DEMO fleet: %d workstations, %d CVEs, %d releases",
                 len(workstations), len(cves), len(releases))

    # Flag legacy seed docs (created before the demo marker existed).
    await db.workstations.update_many({"hostname": {"$in": [h for h, _ in seedmod.HOSTNAMES]}, "demo": {"$exists": False}}, {"$set": {"demo": True}})
    await db.cves.update_many({"cve_id": {"$in": [c[0] for c in seedmod.CVE_SEEDS]}, "demo": {"$exists": False}}, {"$set": {"demo": True}})
    await db.releases.update_many({"version": {"$in": [r[0] for r in seedmod.RELEASES]}, "source": {"$exists": False}, "demo": {"$exists": False}}, {"$set": {"demo": True}})
    demo_ids = [w["id"] async for w in db.workstations.find({"demo": True}, {"id": 1})]
    if demo_ids:
        await db.audit.update_many({"workstation_id": {"$in": demo_ids}, "demo": {"$exists": False}}, {"$set": {"demo": True}})

    # Built-in daily jobs: NVD CVE sync + GitHub release sync (visible/editable under Automations).
    for kind, name in (("nvd_sync", "daily NVD CVE sync"), ("releases_sync", "daily GitHub release sync")):
        if not await db.schedules.find_one({"kind": kind}):
            await db.schedules.insert_one({
                "id": secrets.token_hex(10), "kind": kind, "name": name, "enabled": True,
                "interval_hours": 24, "scope": "all", "created_by": "system", "created_at": _now(),
                "last_run_at": None, "last_run_status": None, "builtin": True,
            })

    # Bootstrap marketplace signing config so /api/marketplace/feed is ready.
    await marketplace.get_or_create_config(db)

    # Kick off the background scheduler (bulk sweeps + sigma sync + marketplace pulls + NVD/GitHub syncs).
    async def _sync_marketplace(job: dict) -> dict:
        return await marketplace.verify_and_import_subscription(db, job)

    async def _sync_sigma(job: dict) -> dict:
        return await sigma_sync.sync_source(db, job)

    asyncio.create_task(sm_scheduler.run_scheduler(
        db,
        run_bulk_sweep=_run_schedule,
        run_sigma_sync=_sync_sigma,
        run_marketplace_sync=_sync_marketplace,
    ))
    asyncio.create_task(fleet_status.status_loop(db))
    log.info("Background scheduler + status loop spawned")


@app.on_event("shutdown")
async def shutdown():
    client.close()


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "*")] if os.environ.get("FRONTEND_URL") else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
