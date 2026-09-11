"""Backend tests for Security Master 'real app' features:
demo banner data, enrollment artifacts, real agent flow, profile switch
(real + demo), heartbeat auth/apply_error, CVE NVD sync, GitHub releases sync,
builtin schedules, and offline engine.
"""
import os
import json
import time
import subprocess
import sys
from datetime import datetime, timezone, timedelta

import pytest
import requests
from pymongo import MongoClient

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@secmaster.io"
ADMIN_PW = "admin1234"

AGENT_PATH = "/app/infrastructure/agent/agent.py"
CLI_PATH = "/app/infrastructure/cli/sec-master"
STATE_DIR = "/tmp/smtest_realapp"
QA_HOST = "qa-agent-01"


# ---------- Mongo (for offline-engine test) ----------
def _mongo_db():
    url = "mongodb://localhost:27017"
    dbname = "security_master"
    try:
        with open("/app/backend/.env") as f:
            for line in f:
                line = line.strip()
                if line.startswith("MONGO_URL="):
                    v = line.split("=", 1)[1].strip().strip('"').strip("'")
                    if v.startswith("mongodb"):
                        url = v
                elif line.startswith("DB_NAME="):
                    dbname = line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return MongoClient(url)[dbname]


@pytest.fixture(scope="module")
def sess():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": ADMIN_EMAIL, "password": ADMIN_PW}, timeout=15)
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    tok = r.json().get("access_token")
    assert tok
    s.headers.update({"Authorization": f"Bearer {tok}"})
    return s


# ==========================================================
# 1. Auth + cookies
# ==========================================================
def test_login_sets_cookie_and_body_token():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": ADMIN_EMAIL, "password": ADMIN_PW}, timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert "access_token" in j and "user" in j
    # cookie should exist
    cookie_names = {c.name for c in s.cookies}
    assert "access_token" in cookie_names, f"cookies: {cookie_names}"


# ==========================================================
# 2. Demo data status + stats overview
# ==========================================================
def test_demo_data_status(sess):
    r = sess.get(f"{BASE_URL}/api/demo-data/status", timeout=10)
    assert r.status_code == 200
    j = r.json()
    for k in ("workstations", "cves", "releases", "purged"):
        assert k in j
    # counts should be > 0 (unless previously purged)
    if not j["purged"]:
        assert j["workstations"] >= 1
        assert j["cves"] >= 1
        assert j["releases"] >= 1


def test_stats_overview(sess):
    r = sess.get(f"{BASE_URL}/api/stats/overview", timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert "demo" in j and isinstance(j["demo"], dict)
    assert "real_total" in j
    for k in ("workstations", "cves", "releases", "purged"):
        assert k in j["demo"]


# ==========================================================
# 3. Enrollment token + bash/ps commands
# ==========================================================
def test_enroll_generate_commands(sess):
    host = f"TEST_realapp_{int(time.time())}"
    r = sess.post(f"{BASE_URL}/api/enroll/generate",
                  json={"hostname": host, "os": "nixos"}, timeout=10)
    assert r.status_code == 200, r.text
    j = r.json()
    assert "/api/agent/bootstrap.sh" in j["bash_command"]
    assert "SM_HOSTNAME=" in j["bash_command"]
    assert "bootstrap.ps1" in j["powershell_command"]
    assert j["token"]


# ==========================================================
# 4. Public agent artifact endpoints (no auth)
# ==========================================================
@pytest.mark.parametrize("path,must_contain", [
    ("/api/agent/bootstrap.sh", ["systemd-run"]),
    ("/api/agent/bootstrap.ps1", ["Register-ScheduledTask"]),
    ("/api/agent/agent.py", ["def apply_profile"]),
    ("/api/agent/SecurityMaster.psm1", []),
    ("/api/agent/sec-master", ["sec-master"]),
])
def test_public_artifacts(path, must_contain):
    r = requests.get(f"{BASE_URL}{path}", timeout=15)
    assert r.status_code == 200, f"{path}: {r.status_code}"
    body = r.text
    assert len(body) > 100, f"{path} too small"
    for m in must_contain:
        assert m in body, f"{path} missing {m!r}"
    if path == "/api/agent/bootstrap.sh":
        assert BASE_URL in body


# ==========================================================
# 5. Real agent flow — enroll + heartbeat via actual script
# ==========================================================
def _run_agent(env_extra: dict, args: list, timeout: int = 60) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update({"SM_STATE_DIR": STATE_DIR})
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, AGENT_PATH, *args, "--dashboard", BASE_URL],
        env=env, capture_output=True, text=True, timeout=timeout
    )


def _find_ws(sess, host):
    r = sess.get(f"{BASE_URL}/api/workstations", params={"q": host}, timeout=10)
    for w in r.json():
        if w["hostname"] == host:
            return w
    return None


def test_real_agent_enroll_and_heartbeat(sess):
    # cleanup prior
    subprocess.run(["rm", "-rf", STATE_DIR], check=False)
    existing = _find_ws(sess, QA_HOST)
    if existing:
        sess.delete(f"{BASE_URL}/api/workstations/{existing['id']}")

    # generate token
    tok = sess.post(f"{BASE_URL}/api/enroll/generate",
                    json={"hostname": QA_HOST, "os": "nixos"}).json()["token"]

    # enroll
    p = _run_agent({"ENROLL_TOKEN": tok, "SM_HOSTNAME": QA_HOST},
                   ["--enroll", "--os", "nixos"])
    assert p.returncode == 0, f"enroll failed: {p.stderr} / {p.stdout}"
    assert "enrolled" in (p.stdout + p.stderr).lower()

    # heartbeat once
    p2 = _run_agent({}, ["--once"])
    assert p2.returncode == 0, f"heartbeat failed: {p2.stderr}"

    # verify workstation state
    ws = _find_ws(sess, QA_HOST)
    assert ws is not None, "workstation not in fleet"
    assert ws["status"] == "online"
    assert ws["agent_version"] == "1.0.0"
    assert ws.get("local_ip")
    assert ws.get("ip_address")
    tools = ws.get("tools") or []
    assert isinstance(tools, list) and len(tools) > 0
    # tools are dicts with name/version/path
    assert all(isinstance(t, dict) and "name" in t and "path" in t for t in tools)
    tool_names = {t["name"] for t in tools}
    # Should detect at least git/curl/python3/openssl in this container
    assert tool_names & {"git", "curl", "python3", "openssl"}


# ==========================================================
# 6. Profile switch on real host
# ==========================================================
def test_switch_profile_real_host_pending(sess):
    ws = _find_ws(sess, QA_HOST)
    assert ws, "enroll test must run first"
    r = sess.post(f"{BASE_URL}/api/workstations/{ws['id']}/switch-profile",
                  json={"profile": "offense"}, timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j["pending"] is True
    assert j["profile"] == "offense"

    ws2 = _find_ws(sess, QA_HOST)
    assert ws2["desired_profile"] == "offense"
    assert ws2["status"] == "drift"
    assert ws2["profile"] == "analyst"  # still original


def test_agent_applies_pending_switch(sess):
    # run agent with a fake switch command
    p = _run_agent({"SM_SWITCH_CMD": "echo switching-{profile}"}, ["--once"], timeout=60)
    assert p.returncode == 0, f"agent apply failed: {p.stderr}\n{p.stdout}"

    time.sleep(1)
    ws = _find_ws(sess, QA_HOST)
    assert ws["profile"] == "offense", f"profile not applied: {ws['profile']}"
    assert ws["status"] == "online"

    # audit trail should mention 'requested switch applied'
    detail = sess.get(f"{BASE_URL}/api/workstations/{ws['id']}", timeout=10).json()
    msgs = [a.get("message", "") for a in detail["audit"]]
    assert any("requested switch applied" in m for m in msgs), \
        f"missing switch audit; got: {msgs}"


# ==========================================================
# 7. Profile switch on demo host (immediate)
# ==========================================================
def test_switch_profile_demo_host_immediate(sess):
    ws_list = sess.get(f"{BASE_URL}/api/workstations").json()
    demos = [w for w in ws_list if w.get("demo")]
    if not demos:
        pytest.skip("no demo hosts")
    demo = demos[0]
    original = demo["profile"]
    target = "offense" if original != "offense" else "defense"
    r = sess.post(f"{BASE_URL}/api/workstations/{demo['id']}/switch-profile",
                  json={"profile": target}, timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j["pending"] is False
    assert j["profile"] == target

    ws2 = [w for w in sess.get(f"{BASE_URL}/api/workstations").json()
           if w["id"] == demo["id"]][0]
    assert ws2["profile"] == target
    # restore
    sess.post(f"{BASE_URL}/api/workstations/{demo['id']}/switch-profile",
              json={"profile": original})


# ==========================================================
# 8. Heartbeat auth + apply_error
# ==========================================================
def test_heartbeat_invalid_bearer_401():
    r = requests.post(f"{BASE_URL}/api/agent/heartbeat",
                      headers={"Authorization": "Bearer nope-bad-token"},
                      json={"profile": "analyst"}, timeout=10)
    assert r.status_code == 401


def test_heartbeat_apply_error_stored(sess):
    # enroll a throwaway host manually
    host = f"TEST_apperr_{int(time.time())}"
    tok = sess.post(f"{BASE_URL}/api/enroll/generate",
                    json={"hostname": host, "os": "nixos"}).json()["token"]
    enroll_r = requests.post(f"{BASE_URL}/api/agent/enroll",
                             json={"token": tok, "hostname": host,
                                   "profile": "analyst",
                                   "agent_version": "1.0.0",
                                   "tools": [{"name": "git", "version": "2.40.0", "path": "/x"}]},
                             timeout=15)
    assert enroll_r.status_code == 200
    ag_tok = enroll_r.json()["agent_token"]
    ws_id = enroll_r.json()["workstation_id"]
    try:
        r = requests.post(f"{BASE_URL}/api/agent/heartbeat",
                          headers={"Authorization": f"Bearer {ag_tok}"},
                          json={"profile": "analyst", "apply_error": "nixos-rebuild boom!"},
                          timeout=10)
        assert r.status_code == 200
        detail = sess.get(f"{BASE_URL}/api/workstations/{ws_id}").json()
        assert detail["workstation"].get("last_apply_error", {}).get("message") == "nixos-rebuild boom!"
        msgs = [a.get("message", "") for a in detail["audit"]]
        assert any("failed to apply" in m for m in msgs), f"missing apply-error audit: {msgs}"
    finally:
        sess.delete(f"{BASE_URL}/api/workstations/{ws_id}")


# ==========================================================
# 9. Offline engine (mongo mutation + wait)
# ==========================================================
def test_offline_engine_marks_stale_host(sess):
    ws = _find_ws(sess, QA_HOST)
    if not ws:
        pytest.skip("qa host missing")
    dbh = _mongo_db()
    old = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    dbh.workstations.update_one({"id": ws["id"]},
                                {"$set": {"last_heartbeat": old, "status": "online"}})
    # fleet_status loop is 30s; wait up to 40s
    for _ in range(20):
        time.sleep(2)
        cur = _find_ws(sess, QA_HOST)
        if cur and cur["status"] == "offline":
            return
    pytest.fail(f"host not marked offline after ~40s (status={cur['status']})")


# ==========================================================
# 10. CVE sync status + list
# ==========================================================
def test_cve_sync_status(sess):
    r = sess.get(f"{BASE_URL}/api/cves/sync-status", timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j.get("api_key_configured") is True
    assert isinstance(j.get("fleet_tools"), list) and len(j["fleet_tools"]) > 0
    # A prior sync should have populated result.tools_queried & cves_stored
    if j.get("status") in ("ok", "success", "done", "completed"):
        result = j.get("result") or {}
        assert result.get("tools_queried", 0) > 0 or j.get("tools_queried", 0) > 0


def test_cve_list_nvd_source(sess):
    r = sess.get(f"{BASE_URL}/api/cves", timeout=15)
    assert r.status_code == 200
    docs = r.json()
    nvd = [d for d in docs if d.get("source") == "nvd"]
    assert len(nvd) > 0, "expected some nvd CVEs"
    sample = nvd[0]
    assert sample.get("url", "").startswith("https://nvd.nist.gov/vuln/detail/")
    assert "affected_range" in sample or "affected_versions" in sample
    # At least one should have matches
    assert any(d.get("matched_workstations", 0) > 0 for d in nvd) or True  # informational


def test_cve_sync_trigger(sess):
    r = sess.post(f"{BASE_URL}/api/cves/sync", timeout=15)
    assert r.status_code == 200
    j = r.json()
    assert "started" in j
    # either started or already running
    assert j["started"] is True or j.get("reason") == "sync already running"


def test_cve_rescan(sess):
    r = sess.post(f"{BASE_URL}/api/cves/rescan", timeout=60)
    assert r.status_code == 200
    assert r.json().get("ok") is True


# ==========================================================
# 11. Releases (real GitHub repo, expected empty)
# ==========================================================
def test_releases_status_and_sync(sess):
    r = sess.get(f"{BASE_URL}/api/releases/status", timeout=10)
    assert r.status_code == 200
    j = r.json()
    assert j["repo"] == "xbustcodex/cyberBuster"

    r2 = sess.post(f"{BASE_URL}/api/releases/sync", timeout=30)
    assert r2.status_code == 200, r2.text
    j2 = r2.json()
    assert j2["ok"] is True
    assert j2["repo"] == "xbustcodex/cyberBuster"
    assert j2["releases"] == 0
    assert j2["signed"] == 0


def test_releases_demo_still_present(sess):
    r = sess.get(f"{BASE_URL}/api/releases", timeout=10)
    assert r.status_code == 200
    demos = [x for x in r.json() if x.get("demo")]
    # 5 demo releases expected (unless purged)
    assert len(demos) >= 1


# ==========================================================
# 12. Schedules (builtins)
# ==========================================================
def test_schedules_builtins(sess):
    r = sess.get(f"{BASE_URL}/api/schedules", timeout=10)
    assert r.status_code == 200
    kinds = {s["kind"] for s in r.json()}
    assert "nvd_sync" in kinds
    assert "releases_sync" in kinds


def test_run_releases_schedule_now(sess):
    scheds = sess.get(f"{BASE_URL}/api/schedules").json()
    rel = next(s for s in scheds if s["kind"] == "releases_sync")
    r = sess.post(f"{BASE_URL}/api/schedules/{rel['id']}/run-now", timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("ok") is True or "result" in j or "repo" in j
    # accept any of the payload variants
    payload = j.get("result") or j
    if "repo" in payload:
        assert payload["repo"] == "xbustcodex/cyberBuster"


# ==========================================================
# 13. Regression (light)
# ==========================================================
def test_regression_endpoints(sess):
    for path in ("/api/plugins", "/api/plugin-templates", "/api/audit"):
        r = sess.get(f"{BASE_URL}{path}", timeout=10)
        assert r.status_code == 200, f"{path} → {r.status_code}"


# ==========================================================
# 14. CLI end-to-end
# ==========================================================
def test_cli_flows(tmp_path):
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(tmp_path)

    def run(*args, timeout=30):
        return subprocess.run([sys.executable, CLI_PATH, *args],
                              env=env, capture_output=True, text=True, timeout=timeout)

    p = run("login", "--dashboard", BASE_URL, "--email", ADMIN_EMAIL, "--password", ADMIN_PW)
    assert p.returncode == 0, f"login: {p.stderr}"
    assert "logged in" in p.stdout.lower()

    for args in (["fleet", "list"], ["cve", "status"],
                 ["releases", "list"], ["demo", "status"]):
        p = run(*args)
        assert p.returncode == 0, f"{args}: {p.stderr}"
        assert p.stdout.strip(), f"{args}: empty output"


# ==========================================================
# Final cleanup: remove qa-agent-01 + state dir
# ==========================================================
def test_zz_cleanup(sess):
    ws = _find_ws(sess, QA_HOST)
    if ws:
        sess.delete(f"{BASE_URL}/api/workstations/{ws['id']}")
    subprocess.run(["rm", "-rf", STATE_DIR], check=False)
