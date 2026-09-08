"""Security Master — Fleet Dashboard API."""
from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

import os
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
    await db.workstations.update_one({"id": ws_id}, {"$set": {"profile": body.profile, "status": "online"}})
    await db.audit.insert_one({
        "id": secrets.token_hex(8),
        "workstation_id": ws_id,
        "hostname": ws["hostname"],
        "kind": "profile_switch",
        "message": f"Profile switched to {body.profile} by {user['email']}",
        "at": _now(),
        "meta": {"by": user["email"], "previous": ws["profile"]},
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
    async for cve in db.cves.find({}):
        matched = 0
        for ws in workstations:
            for t in ws.get("tools", []):
                if t.get("name") == cve.get("affected_tool") and t.get("version") in cve.get("affected_versions", []):
                    matched += 1
                    break
        await db.cves.update_one({"_id": cve["_id"]}, {"$set": {"matched_workstations": matched}})
        updated += 1
    return {"ok": True, "updated": updated}


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
