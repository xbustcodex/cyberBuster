#!/usr/bin/env python3
"""Security Master — cross-platform fleet reporting agent.

Enrolls once (one-time token -> persistent bearer), then posts periodic
heartbeats with the real profile, tool inventory and config hashes. When the
dashboard requests a different profile the agent applies it on the host.

    ENROLL_TOKEN=xxxx python3 agent.py --enroll --dashboard https://dashboard --os nixos
    python3 agent.py --heartbeat --interval 60
    python3 agent.py --once            # single heartbeat, useful for debugging
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

AGENT_VERSION = "1.0.0"
IS_WINDOWS = os.name == "nt"
DASHBOARD = os.environ.get("SM_DASHBOARD", "")
STATE_DIR = os.environ.get("SM_STATE_DIR") or (
    os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "SecMaster") if IS_WINDOWS else "/var/lib/sec-master"
)
TOKEN_FILE = os.path.join(STATE_DIR, "agent.token")
PROFILE_FILE = os.path.join(STATE_DIR, "profile")
PROFILES = ("offense", "defense", "analyst")
VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+){0,2})")

# (fleet tool name, binary, version args)
TOOLS = [
    ("nmap", "nmap", ["--version"]), ("masscan", "masscan", ["--version"]),
    ("ffuf", "ffuf", ["-V"]), ("sqlmap", "sqlmap", ["--version"]),
    ("metasploit", "msfconsole", ["--version"]), ("netexec", "nxc", ["--version"]),
    ("impacket", "impacket-smbclient", ["-h"]), ("sliver", "sliver-client", ["version"]),
    ("ghidra", "ghidraRun", ["--version"]), ("radare2", "r2", ["-v"]),
    ("burpsuite", "burpsuite", ["--version"]), ("evil-winrm", "evil-winrm", ["--version"]),
    ("bloodhound", "bloodhound-python", ["--version"]),
    ("volatility3", "vol", ["--version"]), ("yara", "yara", ["--version"]),
    ("zeek", "zeek", ["--version"]), ("suricata", "suricata", ["-V"]),
    ("wazuh-agent", "wazuh-control", ["info"]), ("velociraptor", "velociraptor", ["version"]),
    ("osquery", "osqueryi", ["--version"]), ("chainsaw", "chainsaw", ["--version"]),
    ("hayabusa", "hayabusa", ["--version"]), ("plaso", "log2timeline.py", ["--version"]),
    ("wireshark", "tshark", ["--version"]), ("tcpdump", "tcpdump", ["--version"]),
    ("mitmproxy", "mitmproxy", ["--version"]), ("vscode", "code", ["--version"]),
    ("docker", "docker", ["--version"]), ("podman", "podman", ["--version"]),
    ("qemu", "qemu-system-x86_64", ["--version"]), ("git", "git", ["--version"]),
    ("age", "age", ["--version"]), ("sops", "sops", ["--version"]),
    ("curl", "curl", ["--version"]), ("openssl", "openssl", ["version"]),
    ("python3", sys.executable, ["--version"]), ("nix", "nix", ["--version"]),
    ("cosign", "cosign", ["version"]), ("sysmon", "sysmon64", ["-h"]),
]


def log(msg: str) -> None:
    print(f"[sec-master] {msg}", flush=True)


def _post(dashboard: str, path: str, body: dict, token: str | None = None) -> dict:
    req = urllib.request.Request(
        f"{dashboard.rstrip('/')}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": f"sec-master-agent/{AGENT_VERSION}",
                 **({"Authorization": f"Bearer {token}"} if token else {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return 127, str(e)


def detect_tools() -> list[dict]:
    out = []
    for name, binary, args in TOOLS:
        path = binary if os.path.isabs(binary) else shutil.which(binary)
        if not path:
            continue
        _, text = _run([path, *args], timeout=6)
        m = VERSION_RE.search(text)
        out.append({"name": name, "version": m.group(1) if m else "unknown", "path": path})
    return out


def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def flake_hash() -> str | None:
    if IS_WINDOWS:
        return None
    for p in ("/etc/nixos/flake.lock", "/etc/nixos/configuration.nix"):
        digest = _sha256_file(p)
        if digest:
            return "sha256-" + digest[:32]
    if shutil.which("nixos-version"):
        rc, text = _run(["nixos-version", "--json"])
        if rc == 0:
            try:
                rev = json.loads(text).get("configurationRevision") or json.loads(text).get("nixpkgsRevision")
                if rev:
                    return "git-" + rev[:16]
            except ValueError:
                pass
    return None


def dsc_hash() -> str | None:
    if not IS_WINDOWS:
        return None
    for name in ("profiles.dsc.ps1", "SecurityMaster.psm1"):
        digest = _sha256_file(os.path.join(STATE_DIR, name))
        if digest:
            return "SHA256:" + digest[:24].upper()
    return None


def current_profile() -> str:
    try:
        with open(PROFILE_FILE) as fh:
            p = fh.read().strip()
            if p in PROFILES:
                return p
    except OSError:
        pass
    env_p = os.environ.get("SM_PROFILE", "")
    return env_p if env_p in PROFILES else "analyst"


def _save_profile(p: str) -> None:
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(PROFILE_FILE, "w") as fh:
        fh.write(p)


def local_ip() -> str | None:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def apply_profile(profile: str) -> tuple[bool, str]:
    """Apply a profile on this host. Override with SM_SWITCH_CMD='... {profile}'."""
    custom = os.environ.get("SM_SWITCH_CMD")
    if custom:
        cmd = custom.format(profile=profile)
        rc, text = _run(["/bin/sh", "-c", cmd] if not IS_WINDOWS else ["cmd", "/c", cmd], timeout=1800)
    elif IS_WINDOWS:
        module = os.path.join(STATE_DIR, "SecurityMaster.psm1")
        rc, text = _run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                         f"Import-Module '{module}'; Set-SMProfile -Profile {profile}"], timeout=1800)
    elif os.path.exists("/etc/NIXOS") and shutil.which("nixos-rebuild"):
        rc, text = _run(["nixos-rebuild", "switch", "--specialisation", profile], timeout=3600)
    else:
        return False, "no switch backend on this host (set SM_SWITCH_CMD)"
    if rc == 0:
        _save_profile(profile)
        log(f"profile applied: {profile}")
        return True, ""
    err = text.strip().splitlines()[-1] if text.strip() else f"exit {rc}"
    log(f"profile apply failed ({profile}): {err}")
    return False, err[:300]


def build_heartbeat(apply_error: str = "") -> dict:
    body = {
        "profile": current_profile(),
        "agent_version": AGENT_VERSION,
        "flake_hash": flake_hash(),
        "dsc_hash": dsc_hash(),
        "tools": detect_tools(),
        "local_ip": local_ip(),
        "os_release": platform.platform(),
    }
    if apply_error:
        body["apply_error"] = apply_error
    return body


def enroll(token: str, hostname: str, os_kind: str, dashboard: str) -> str:
    body = {"token": token, "hostname": hostname, "os": os_kind, **build_heartbeat()}
    resp = _post(dashboard, "/api/agent/enroll", body)
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(TOKEN_FILE, "w") as fh:
        fh.write(resp["agent_token"])
    if not IS_WINDOWS:
        os.chmod(TOKEN_FILE, 0o600)
    _save_profile(body["profile"])
    log(f"enrolled workstation_id={resp['workstation_id']} token stored in {TOKEN_FILE}")
    return resp["agent_token"]


def load_token() -> str | None:
    tok = os.environ.get("SM_AGENT_TOKEN")
    if tok:
        return tok
    try:
        with open(TOKEN_FILE) as fh:
            return fh.read().strip() or None
    except OSError:
        return None


def heartbeat_once(token: str, dashboard: str, allow_apply: bool, apply_error: str = "") -> tuple[int, str]:
    resp = _post(dashboard, "/api/agent/heartbeat", build_heartbeat(apply_error), token=token)
    desired = resp.get("desired_profile")
    interval = int(resp.get("next_check_in_seconds") or 60)
    log(f"heartbeat ok profile={current_profile()} desired={desired or '-'}")
    if desired and desired in PROFILES and desired != current_profile():
        if not allow_apply:
            return interval, "auto-apply disabled on this agent (--no-apply)"
        ok, err = apply_profile(desired)
        if ok:
            _post(dashboard, "/api/agent/heartbeat", build_heartbeat(), token=token)
        return interval, err
    return interval, ""


def heartbeat_loop(token: str, interval: int, dashboard: str, allow_apply: bool) -> int:
    apply_error = ""
    while True:
        try:
            next_in, apply_error = heartbeat_once(token, dashboard, allow_apply, apply_error)
            interval = max(15, next_in)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log("agent token rejected (401) — re-enroll this host")
                return 3
            log(f"heartbeat failed: HTTP {e.code}")
        except Exception as e:
            log(f"heartbeat failed: {e}")
        time.sleep(interval)


def main() -> int:
    p = argparse.ArgumentParser(description="Security Master fleet agent")
    p.add_argument("--enroll", action="store_true")
    p.add_argument("--heartbeat", action="store_true")
    p.add_argument("--once", action="store_true", help="send a single heartbeat and exit")
    p.add_argument("--dashboard", default=DASHBOARD)
    p.add_argument("--interval", type=int, default=60)
    p.add_argument("--os", default="windows" if IS_WINDOWS else ("nixos" if os.path.exists("/etc/NIXOS") else "linux"))
    p.add_argument("--no-apply", action="store_true", help="report desired profile but never apply it")
    args = p.parse_args()

    if not args.dashboard:
        print("dashboard URL missing (--dashboard or SM_DASHBOARD)", file=sys.stderr)
        return 2
    os_kind = "windows" if args.os == "windows" else "nixos"

    if args.enroll:
        tok = os.environ.get("ENROLL_TOKEN")
        host = os.environ.get("SM_HOSTNAME") or os.environ.get("HOSTNAME") or platform.node()
        if not tok:
            print("ENROLL_TOKEN missing", file=sys.stderr)
            return 2
        enroll(tok, host, os_kind, args.dashboard)
        return 0

    if args.heartbeat or args.once:
        tok = load_token()
        if not tok:
            print(f"no agent token (SM_AGENT_TOKEN or {TOKEN_FILE}) — run --enroll first", file=sys.stderr)
            return 2
        if args.once:
            heartbeat_once(tok, args.dashboard, not args.no_apply)
            return 0
        return heartbeat_loop(tok, args.interval, args.dashboard, not args.no_apply)

    p.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
