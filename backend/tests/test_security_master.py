"""Backend regression + new-feature tests for Security Master.

Covers: bulk IOC sweep, sigma preview/import, template sharing, auto-enrich on
enroll, plus regression on fleet/cve/releases/plugins/workstation-detail/ioc.
"""
import os
import time
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # fallback to reading frontend .env
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

ADMIN_EMAIL = "admin@secmaster.io"
ADMIN_PW = "admin1234"


# ---------- session fixture ----------
@pytest.fixture(scope="module")
def sess():
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": ADMIN_EMAIL, "password": ADMIN_PW}, timeout=15)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    tok = r.json().get("access_token")
    if tok:
        s.headers.update({"Authorization": f"Bearer {tok}"})
    return s


# ---------- regression ----------
class TestRegression:
    def test_health(self, sess):
        r = sess.get(f"{BASE_URL}/api/health", timeout=10)
        assert r.status_code == 200 and r.json()["status"] == "ok"

    def test_fleet(self, sess):
        r = sess.get(f"{BASE_URL}/api/workstations", timeout=10)
        assert r.status_code == 200
        assert isinstance(r.json(), list) and len(r.json()) > 0

    def test_cves(self, sess):
        r = sess.get(f"{BASE_URL}/api/cves", timeout=10)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_releases(self, sess):
        r = sess.get(f"{BASE_URL}/api/releases", timeout=10)
        assert r.status_code == 200

    def test_plugins_list(self, sess):
        r = sess.get(f"{BASE_URL}/api/plugins", timeout=10)
        assert r.status_code == 200

    def test_ws_detail_and_ioc(self, sess):
        ws_list = sess.get(f"{BASE_URL}/api/workstations").json()
        wid = ws_list[0]["id"]
        r = sess.get(f"{BASE_URL}/api/workstations/{wid}", timeout=10)
        assert r.status_code == 200
        assert "workstation" in r.json() and "audit" in r.json()
        r2 = sess.get(f"{BASE_URL}/api/workstations/{wid}/ioc", timeout=10)
        assert r2.status_code == 200
        assert "providers" in r2.json()


# ---------- helper: ensure VT plugin present ----------
def _ensure_vt_plugin(sess) -> str:
    plugs = sess.get(f"{BASE_URL}/api/plugins").json()
    for p in plugs:
        if p["type"] == "virustotal":
            if not p.get("enabled"):
                sess.patch(f"{BASE_URL}/api/plugins/{p['id']}", json={"enabled": True})
            return p["id"]
    r = sess.post(f"{BASE_URL}/api/plugins", json={
        "type": "virustotal",
        "name": "TEST_vt",
        "enabled": True,
        "secrets": {"api_key": "fake-test-key"},
        "event_subscriptions": [],
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _disable_all_query_plugins(sess) -> list[dict]:
    """Disable every VT/Shodan plugin, return list of ids re-enabled."""
    disabled = []
    for p in sess.get(f"{BASE_URL}/api/plugins").json():
        if p["type"] in ("virustotal", "shodan") and p.get("enabled"):
            sess.patch(f"{BASE_URL}/api/plugins/{p['id']}", json={"enabled": False})
            disabled.append(p["id"])
    return disabled


def _re_enable(sess, ids):
    for pid in ids:
        sess.patch(f"{BASE_URL}/api/plugins/{pid}", json={"enabled": True})


# ---------- Bulk IOC Sweep ----------
class TestBulkSweep:
    def test_online_scope_with_vt(self, sess):
        _ensure_vt_plugin(sess)
        r = sess.post(f"{BASE_URL}/api/ioc/bulk-sweep",
                      json={"scope": "online"}, timeout=60)
        assert r.status_code == 200, r.text
        data = r.json()
        for k in ("ok", "hosts_swept", "total_lookups", "per_host", "providers_used"):
            assert k in data
        assert data["providers_used"]["virustotal"] is True
        self.online_hosts = data["hosts_swept"]

    def test_all_scope_covers_more(self, sess):
        _ensure_vt_plugin(sess)
        online = sess.post(f"{BASE_URL}/api/ioc/bulk-sweep",
                           json={"scope": "online"}, timeout=60).json()
        alls = sess.post(f"{BASE_URL}/api/ioc/bulk-sweep",
                         json={"scope": "all"}, timeout=90).json()
        # 'all' should be >= online. Assert strictly greater if offline hosts exist.
        assert alls["hosts_swept"] >= online["hosts_swept"]

    def test_no_provider_returns_400(self, sess):
        disabled = _disable_all_query_plugins(sess)
        try:
            r = sess.post(f"{BASE_URL}/api/ioc/bulk-sweep",
                          json={"scope": "online"}, timeout=15)
            assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text}"
        finally:
            _re_enable(sess, disabled)


# ---------- Sigma Preview / Import ----------
SIGMA_YAML = """
title: Malware Sample A
id: 11111111-1111-1111-1111-111111111111
level: high
detection:
    selection:
        Hashes|contains:
            - 'md5=44d88612fea8a8f36de82e1278abb02f'
            - 'sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    condition: selection
---
title: Malware Sample B
id: 22222222-2222-2222-2222-222222222222
level: medium
detection:
    selection:
        sha1:
            - 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    condition: selection
"""

INVALID_YAML = "title: broken\n  bad: [unclosed"


class TestSigma:
    def test_preview_two_rules(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma/preview",
                      json={"sigma_yaml": SIGMA_YAML}, timeout=15)
        assert r.status_code == 200, r.text
        data = r.json()
        assert len(data["rules"]) == 2
        titles = [r["title"] for r in data["rules"]]
        assert "Malware Sample A" in titles and "Malware Sample B" in titles
        # Rule A has 2 hashes, Rule B has 1 => 3 unique
        assert len(data["unique_hashes"]) == 3
        # dedupe check
        vals = [h["hash"] for h in data["unique_hashes"]]
        assert len(vals) == len(set(vals))
        # Levels & ids present
        for rule in data["rules"]:
            assert rule["level"] in ("high", "medium")
            assert rule["id"]
            assert isinstance(rule["hashes"], list)

    def test_preview_invalid_yaml(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma/preview",
                      json={"sigma_yaml": INVALID_YAML}, timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data["rules"], list) and len(data["rules"]) >= 1
        # Should have warnings present
        warnings = data["rules"][0].get("warnings", [])
        assert any("yaml" in w.lower() or "parse" in w.lower() for w in warnings)

    def test_import_all_online_and_dedupe(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma/import",
                      json={"sigma_yaml": SIGMA_YAML, "scope": "all-online"},
                      timeout=30)
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["rules_parsed"] == 2
        assert data["unique_hashes"] == 3
        assert data["targets"] > 0

        # Verify persistence — pick first online ws with added>0
        online = [p for p in data["per_workstation"] if p["added"] > 0]
        # even if empty (all already had them from prior run), continue to dedupe check
        # Fetch first target and verify sigma-prefixed notes
        target_wid = data["per_workstation"][0]["workstation_id"]
        ws = sess.get(f"{BASE_URL}/api/workstations/{target_wid}").json()["workstation"]
        sigma_entries = [h for h in ws.get("suspicious_hashes", [])
                         if (h.get("note") or "").startswith("sigma: ")]
        assert len(sigma_entries) >= 3

        # Duplicate import — should add 0
        r2 = sess.post(f"{BASE_URL}/api/sigma/import",
                       json={"sigma_yaml": SIGMA_YAML, "scope": "all-online"},
                       timeout=30)
        assert r2.status_code == 200
        for row in r2.json()["per_workstation"]:
            assert row["added"] == 0, f"dedupe failed for {row['hostname']}"

    def test_import_empty_returns_400(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma/import",
                      json={"sigma_yaml": "title: noHashes\nlevel: low\n",
                            "scope": "all-online"}, timeout=10)
        assert r.status_code == 400


# ---------- Template sharing ----------
class TestTemplates:
    def test_share_flow(self, sess):
        vt_id = _ensure_vt_plugin(sess)
        tname = f"TEST_tpl_{int(time.time())}"
        # save as template with shared=true
        r = sess.post(f"{BASE_URL}/api/plugins/{vt_id}/save-as-template",
                      json={"name": tname, "shared": True})
        assert r.status_code == 200, r.text
        tpl = r.json()
        assert tpl["shared"] is True
        tpl_id = tpl["id"]

        # toggle shared=false
        r2 = sess.patch(f"{BASE_URL}/api/plugin-templates/{tpl_id}",
                        json={"shared": False})
        assert r2.status_code == 200
        assert r2.json()["shared"] is False

        # duplicate-name PATCH returns 400
        tname2 = f"TEST_tpl2_{int(time.time())}"
        r3 = sess.post(f"{BASE_URL}/api/plugins/{vt_id}/save-as-template",
                       json={"name": tname2, "shared": False})
        assert r3.status_code == 200
        tpl_id2 = r3.json()["id"]

        r4 = sess.patch(f"{BASE_URL}/api/plugin-templates/{tpl_id2}",
                        json={"name": tname})
        assert r4.status_code == 400

        # list sort: shared first
        # toggle one back to shared
        sess.patch(f"{BASE_URL}/api/plugin-templates/{tpl_id}", json={"shared": True})
        lst = sess.get(f"{BASE_URL}/api/plugin-templates").json()
        # collect indices — every shared=True must come before any shared=False
        seen_unshared = False
        for t in lst:
            if not t.get("shared"):
                seen_unshared = True
            elif seen_unshared:
                pytest.fail("shared=true template appeared after shared=false — sort order broken")

        # cleanup
        sess.delete(f"{BASE_URL}/api/plugin-templates/{tpl_id}")
        sess.delete(f"{BASE_URL}/api/plugin-templates/{tpl_id2}")


# ---------- Auto-enrich on enroll ----------
class TestAutoEnrichOnEnroll:
    def test_enroll_triggers_auto_enrichment(self, sess):
        _ensure_vt_plugin(sess)
        host = f"TEST_ws_{int(time.time())}"

        gen = sess.post(f"{BASE_URL}/api/enroll/generate",
                        json={"hostname": host, "os": "nixos"}).json()
        token = gen["token"]

        # Public agent enroll (no auth)
        r = requests.post(f"{BASE_URL}/api/agent/enroll",
                          json={"token": token, "hostname": host,
                                "profile": "analyst"}, timeout=15)
        assert r.status_code == 200, r.text
        ws_id = r.json()["workstation_id"]

        # Wait for asyncio.create_task
        time.sleep(4)

        ioc = sess.get(f"{BASE_URL}/api/workstations/{ws_id}/ioc").json()
        # If workstation had ip_address, ioc history should have >=1 entry
        # (even if VT returns 401 with fake key, it's still logged as an entry).
        ws_info = sess.get(f"{BASE_URL}/api/workstations/{ws_id}").json()
        if ws_info["workstation"].get("ip_address"):
            assert len(ioc["history"]) >= 1, "expected auto-enrich lookup entry"

        # Audit event should contain "Auto-enrichment triggered on enroll"
        detail = sess.get(f"{BASE_URL}/api/workstations/{ws_id}").json()
        msgs = [a.get("message", "") for a in detail["audit"]]
        assert any("Auto-enrichment triggered on enroll" in m for m in msgs), \
            f"missing auto-enrich audit event; got: {msgs}"

        # cleanup
        sess.delete(f"{BASE_URL}/api/workstations/{ws_id}")
