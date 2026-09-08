"""Pydantic models for Security Master dashboard."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr, ConfigDict
import uuid


ProfileName = Literal["offense", "defense", "analyst"]
OSKind = Literal["nixos", "windows"]
Severity = Literal["critical", "high", "medium", "low"]


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Auth ----------
class UserPublic(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    email: EmailStr
    name: str
    role: str = "admin"
    created_at: str


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=80)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------- Workstations / Agent ----------
class ToolVersion(BaseModel):
    name: str
    version: str


class Workstation(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uuid)
    hostname: str
    os: OSKind
    profile: ProfileName = "analyst"
    agent_version: str = "0.1.0"
    flake_hash: Optional[str] = None
    dsc_hash: Optional[str] = None
    tools: List[ToolVersion] = []
    tags: List[str] = []
    enrolled_at: str = Field(default_factory=_now)
    last_heartbeat: Optional[str] = None
    status: Literal["online", "drift", "offline"] = "online"
    ip_address: Optional[str] = None


class HeartbeatPayload(BaseModel):
    hostname: Optional[str] = None
    profile: ProfileName
    agent_version: str
    flake_hash: Optional[str] = None
    dsc_hash: Optional[str] = None
    tools: List[ToolVersion] = []
    ip_address: Optional[str] = None


class ProfileSwitchRequest(BaseModel):
    profile: ProfileName


# ---------- Enrollment ----------
class EnrollTokenOut(BaseModel):
    token: str
    hostname: str
    os: OSKind
    expires_at: str
    bash_command: str
    powershell_command: str


class EnrollGenerateRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=64)
    os: OSKind


# ---------- CVE ----------
class CveRecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uuid)
    cve_id: str
    severity: Severity
    cvss: float
    published: str
    summary: str
    affected_tool: str
    affected_versions: List[str] = []
    remediation: str
    matched_workstations: int = 0


# ---------- Signed Releases ----------
class SignedRelease(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uuid)
    version: str
    commit_sha: str
    signature_status: Literal["valid", "invalid", "unsigned"] = "valid"
    signer: str
    published_at: str
    changelog: str
    channel: Literal["stable", "beta", "nightly"] = "stable"


# ---------- Audit ----------
class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=_uuid)
    workstation_id: str
    hostname: str
    kind: Literal["profile_switch", "heartbeat", "enroll", "cve_match", "tool_update"]
    message: str
    at: str = Field(default_factory=_now)
    meta: dict = {}
