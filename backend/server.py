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
    await db.workstations.update_one({"id": ws_id}, {"$set": {"profile": body.profile, "status": "online"}})
    await db.audit.insert_one({
        "id": secrets.token_hex(8),
        "workstation_id": ws_id,
        "hostname": ws["hostname"],
        "kind": "profile_switch",
        "message": f"Profile switched to {body.profile} by {user['email']}",
        "at": _now(),
        "meta": {"by": user["email"], "previous": previous},
    })
    await sm_plugins.dispatch(db, "workstation.profile_switched", {
        "hostname": ws["hostname"], "workstation_id": ws_id,
        "profile": body.profile, "previous": previous, "by": user["email"],
    })
    return {"ok": True, "profile": body.profile}


@api.delete("/workstations/{ws_id}")
async def delete_workstation(ws_id: str, _user=Depends(get_current_user)):
    res = await db.workstations.delete_one({"id": ws_id})
    if res.deleted_count == 0:
        raise HTTPException(404, "Workstation not found")
    await db.audit.delete_many({"workstation_id": ws_id})
    return {"ok": True}


# ============================================================
# ENROLLMENT
# ============================================================
@api.post("/enroll/generate", response_model=EnrollTokenOut)
async def generate_enroll_token(body: EnrollGenerateRequest, _user=Depends(get_current_user)):
    token = secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    await db.enroll_tokens.insert_one({
        "token": token,
        "hostname": body.hostname,
        "os": body.os,
        "expires_at": expires,
        "used": False,
    })
    backend = os.environ.get("FRONTEND_URL", "http://localhost:8001").rstrip("/")
    bash_cmd = (
        f'curl -sSL {backend}/api/agent/bootstrap.sh | '
        f'ENROLL_TOKEN="{token}" HOSTNAME="{body.hostname}" bash'
    )
    ps_cmd = (
        f'iwr {backend}/api/agent/bootstrap.ps1 -UseB | '
        f'iex; Invoke-SMEnroll -Token "{token}" -Hostname "{body.hostname}"'
    )
    return EnrollTokenOut(
        token=token, hostname=body.hostname, os=body.os,
        expires_at=expires, bash_command=bash_cmd, powershell_command=ps_cmd,
    )


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
    ws = {
        "id": ws_id,
        "hostname": body.get("hostname") or tok["hostname"],
        "os": tok["os"],
        "profile": body.get("profile", "analyst"),
        "agent_version": body.get("agent_version", "0.1.0"),
        "flake_hash": body.get("flake_hash"),
        "dsc_hash": body.get("dsc_hash"),
        "tools": body.get("tools", []),
        "tags": [tok["os"], body.get("profile", "analyst")],
        "enrolled_at": _now(),
        "last_heartbeat": _now(),
        "status": "online",
        "ip_address": request.client.host if request.client else None,
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
    return {"workstation_id": ws_id, "agent_token": agent_token}


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
    updates = {"last_heartbeat": _now(), "status": "online"}
    for field in ("profile", "agent_version", "flake_hash", "dsc_hash", "tools", "ip_address"):
        if field in body and body[field] is not None:
            updates[field] = body[field]
    await db.workstations.update_one({"id": ws["id"]}, {"$set": updates})
    return {"ok": True, "next_check_in_seconds": 60}


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


# ============================================================
# RELEASES
# ============================================================
@api.get("/releases")
async def list_releases(_user=Depends(get_current_user)):
    docs = await db.releases.find({}, {"_id": 0}).sort("published_at", -1).to_list(200)
    return docs


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
        "by_profile": by_profile,
        "by_os": by_os,
        "by_status": by_status,
        "cve_total": len(cves),
        "cve_by_severity": cve_sev,
        "latest_release": latest_release,
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
    docs = await db.plugin_templates.find({}).sort("created_at", -1).to_list(200)
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
    }
    await db.plugin_templates.insert_one(doc)
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

        # VirusTotal
        if vt and ttype in ("ip", "hash", "domain"):
            vt_kind = "hash" if ttype == "hash" else ttype
            r = await sm_plugins.query(db, vt, {"kind": vt_kind, "value": tval})
            summary = _summarize_vt(r.get("response", "")) if r.get("status") == "ok" else {}
            rec = {
                "id": secrets.token_hex(8),
                "workstation_id": ws_id,
                "hostname": ws.get("hostname"),
                "target_type": ttype, "target_value": tval,
                "provider": "virustotal",
                "status": r.get("status"),
                "http_status": r.get("http_status"),
                "summary": summary,
                "raw_snippet": (r.get("response") or "")[:600],
                "at": _now(),
            }
            await db.ioc_lookups.insert_one(rec)
            results.append(rec)

        # Shodan (IP only)
        if sh and ttype == "ip":
            r = await sm_plugins.query(db, sh, {"ip": tval})
            summary = _summarize_shodan(r.get("response", "")) if r.get("status") == "ok" else {}
            rec = {
                "id": secrets.token_hex(8),
                "workstation_id": ws_id,
                "hostname": ws.get("hostname"),
                "target_type": ttype, "target_value": tval,
                "provider": "shodan",
                "status": r.get("status"),
                "http_status": r.get("http_status"),
                "summary": summary,
                "raw_snippet": (r.get("response") or "")[:600],
                "at": _now(),
            }
            await db.ioc_lookups.insert_one(rec)
            results.append(rec)

    # Strip _id for JSON response
    for r in results: r.pop("_id", None)
    return {"ok": True, "count": len(results), "results": results,
            "providers_used": {"virustotal": bool(vt), "shodan": bool(sh)}}


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

    if await db.workstations.count_documents({}) == 0:
        workstations = seedmod.build_workstations()
        await db.workstations.insert_many(workstations)
        cves = seedmod.build_cves(workstations)
        await db.cves.insert_many(cves)
        releases = seedmod.build_releases()
        await db.releases.insert_many(releases)
        audit = seedmod.build_audit(workstations)
        if audit:
            await db.audit.insert_many(audit)
        log.info("Seeded fleet: %d workstations, %d CVEs, %d releases",
                 len(workstations), len(cves), len(releases))


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
