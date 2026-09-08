#!/usr/bin/env python3
"""Security Master — cross-platform fleet reporting agent.

Small daemon: enrolls once (exchange one-time token for a persistent bearer),
then posts periodic heartbeats with profile + tool inventory + hashes.

Usage
-----
    # First-time enrollment
    ENROLL_TOKEN=xxxx HOSTNAME=host-01 python3 agent.py --enroll --os nixos

    # Long-running heartbeat loop
    SM_AGENT_TOKEN=xxxx python3 agent.py --heartbeat --interval 60

    # One-shot simulator: spawns N fake workstations against the dashboard API
    python3 agent.py --simulate 5 --dashboard https://dashboard.example
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import sys
import time
import urllib.request
import urllib.error

DASHBOARD = os.environ.get("SM_DASHBOARD", "http://localhost:8001")
STATE_FILE = os.environ.get("SM_STATE_FILE", "/var/lib/sec-master/agent.state") if os.name == "posix" else "sm_agent.state"


def _post(path: str, body: dict, token: str | None = None, dashboard: str = DASHBOARD) -> dict:
    req = urllib.request.Request(
        f"{dashboard.rstrip('/')}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _detect_tools() -> list[dict]:
    candidates = [
        ("nmap", "nmap --version"), ("git", "git --version"),
        ("docker", "docker --version"), ("python3", "python3 --version"),
        ("wireshark", "wireshark --version"), ("radare2", "r2 -v"),
    ]
    out = []
    for name, cmd in candidates:
        try:
            r = subprocess.run(cmd.split(), capture_output=True, timeout=3, text=True)
            first = (r.stdout or r.stderr).splitlines()[0] if r.stdout or r.stderr else ""
            ver = "".join(c for c in first.split(name)[-1] if c in "0123456789.")[:12].strip(".") or "unknown"
            out.append({"name": name, "version": ver})
        except Exception:
            continue
    return out


def enroll(token: str, hostname: str, os_kind: str, dashboard: str = DASHBOARD) -> str:
    body = {
        "token": token, "hostname": hostname, "os": os_kind,
        "profile": "analyst", "agent_version": "0.1.0",
        "flake_hash": None if os_kind == "windows" else "sha256-boot-" + os.urandom(4).hex(),
        "dsc_hash": ("SHA256:" + os.urandom(4).hex().upper()) if os_kind == "windows" else None,
        "tools": _detect_tools(),
    }
    resp = _post("/api/agent/enroll", body, dashboard=dashboard)
    agent_token = resp["agent_token"]
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True) if os.path.dirname(STATE_FILE) else None
    with open(STATE_FILE, "w") as fh:
        fh.write(agent_token)
    print(f"[sec-master] enrolled workstation_id={resp['workstation_id']}")
    return agent_token


def heartbeat_loop(token: str, interval: int, profile: str = "analyst", dashboard: str = DASHBOARD) -> None:
    while True:
        try:
            _post("/api/agent/heartbeat", {
                "profile": profile, "agent_version": "0.1.0",
                "tools": _detect_tools(),
                "flake_hash": "sha256-" + os.urandom(4).hex(),
            }, token=token, dashboard=dashboard)
            print(f"[sec-master] heartbeat sent (profile={profile})")
        except urllib.error.HTTPError as e:
            print(f"[sec-master] heartbeat failed: {e}")
        time.sleep(interval)


def simulate(count: int, dashboard: str) -> None:
    """Spawn N fake workstations via the admin API. Requires admin creds via env."""
    email = os.environ.get("SM_ADMIN_EMAIL", "admin@secmaster.io")
    password = os.environ.get("SM_ADMIN_PASSWORD", "admin1234")

    # login
    req = urllib.request.Request(
        f"{dashboard.rstrip('/')}/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        login_resp = json.loads(r.read())
    admin_token = login_resp["access_token"]

    profiles = ["offense", "defense", "analyst"]
    for i in range(count):
        host = f"sim-agent-{os.urandom(2).hex()}"
        os_kind = random.choice(["nixos", "windows"])

        req = urllib.request.Request(
            f"{dashboard.rstrip('/')}/api/enroll/generate",
            data=json.dumps({"hostname": host, "os": os_kind}).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {admin_token}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            gen = json.loads(r.read())

        prof = random.choice(profiles)
        agent_token = enroll(gen["token"], host, os_kind, dashboard=dashboard)
        _post("/api/agent/heartbeat", {
            "profile": prof, "agent_version": "0.1.0",
            "tools": _detect_tools(),
        }, token=agent_token, dashboard=dashboard)
        print(f"[sim] {host} ({os_kind}) enrolled → profile={prof}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--enroll", action="store_true")
    p.add_argument("--heartbeat", action="store_true")
    p.add_argument("--simulate", type=int, default=0)
    p.add_argument("--dashboard", default=DASHBOARD)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--os", default="nixos" if platform.system() != "Windows" else "windows")
    p.add_argument("--profile", default="analyst")
    args = p.parse_args()

    if args.simulate:
        simulate(args.simulate, args.dashboard); return 0
    if args.enroll:
        tok = os.environ.get("ENROLL_TOKEN")
        host = os.environ.get("HOSTNAME") or platform.node()
        if not tok:
            print("ENROLL_TOKEN missing", file=sys.stderr); return 2
        enroll(tok, host, args.os, dashboard=args.dashboard); return 0
    if args.heartbeat:
        tok = os.environ.get("SM_AGENT_TOKEN")
        if not tok and os.path.exists(STATE_FILE):
            tok = open(STATE_FILE).read().strip()
        if not tok:
            print("SM_AGENT_TOKEN missing", file=sys.stderr); return 2
        heartbeat_loop(tok, args.interval, args.profile, args.dashboard); return 0
    p.print_help(); return 1


if __name__ == "__main__":
    sys.exit(main())
