"""Backend tests for Automations iteration 3:
Scheduled Sweeps, Sigma Rule Repo Sync, and Team Template Marketplace (HMAC-SHA256 signed feed).

Guidelines followed:
- Schedules created with interval_hours=720 so the background scheduler never
  auto-fires them during the test window; explicit run-now used instead.
- Sigma sync-now against real GitHub is NOT invoked; we only validate
  parse_repo_url behaviour via the create endpoint (multiple URL shapes).
- Marketplace loopback uses the feed_url returned by /api/marketplace/info,
  which is served by the same FastAPI app under REACT_APP_BACKEND_URL.
"""
import base64
import hashlib
import hmac
import json
import os
import time

import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

# In this preview env, /api/marketplace/info returns a feed_url pointing at the
# internal cluster hostname which is intermittently 502/403. Per the agent-to-
# agent testing note we substitute with the localhost loopback URL for the feed
# fetch. This is the same FastAPI app so signature semantics are identical.
LOOPBACK = "http://localhost:8001"

ADMIN_EMAIL = "admin@secmaster.io"
ADMIN_PW = "admin1234"


def _feed_loopback(feed_id: str) -> str:
    return f"{LOOPBACK}/api/marketplace/feed?fid={feed_id}"


# ---------- session ----------
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


# ============================================================
# SCHEDULES CRUD
# ============================================================
class TestSchedules:
    def test_full_crud_and_runs(self, sess):
        # CREATE with a very long interval (720h) so the auto-scheduler never fires during test
        r = sess.post(f"{BASE_URL}/api/schedules",
                      json={"scope": "online", "interval_hours": 720,
                            "name": "TEST_sched_ok", "enabled": True}, timeout=15)
        assert r.status_code == 200, r.text
        sched = r.json()
        assert sched["scope"] == "online"
        assert sched["interval_hours"] == 720
        assert sched["enabled"] is True
        assert sched["kind"] == "bulk_sweep"
        assert "_id" not in sched
        sid = sched["id"]

        # LIST
        lst = sess.get(f"{BASE_URL}/api/schedules", timeout=10)
        assert lst.status_code == 200
        assert any(s["id"] == sid for s in lst.json())

        # PATCH toggle enabled=False
        p = sess.patch(f"{BASE_URL}/api/schedules/{sid}",
                       json={"enabled": False}, timeout=10)
        assert p.status_code == 200
        assert p.json()["enabled"] is False

        # PATCH interval (valid)
        p2 = sess.patch(f"{BASE_URL}/api/schedules/{sid}",
                        json={"interval_hours": 168}, timeout=10)
        assert p2.status_code == 200
        assert p2.json()["interval_hours"] == 168

        # RUN NOW — updates last_run_status
        run = sess.post(f"{BASE_URL}/api/schedules/{sid}/run-now", timeout=90)
        assert run.status_code == 200, run.text
        assert run.json()["ok"] is True

        after = sess.get(f"{BASE_URL}/api/schedules").json()
        me = next(s for s in after if s["id"] == sid)
        assert me["last_run_status"] == "ok"
        assert me["last_run_at"] is not None

        # DELETE
        d = sess.delete(f"{BASE_URL}/api/schedules/{sid}", timeout=10)
        assert d.status_code == 200
        # verify removed
        after2 = sess.get(f"{BASE_URL}/api/schedules").json()
        assert not any(s["id"] == sid for s in after2)

    def test_invalid_interval_zero(self, sess):
        r = sess.post(f"{BASE_URL}/api/schedules",
                      json={"scope": "online", "interval_hours": 0}, timeout=10)
        assert r.status_code == 400

    def test_invalid_interval_too_big(self, sess):
        r = sess.post(f"{BASE_URL}/api/schedules",
                      json={"scope": "online", "interval_hours": 721}, timeout=10)
        assert r.status_code == 400

    def test_invalid_scope(self, sess):
        r = sess.post(f"{BASE_URL}/api/schedules",
                      json={"scope": "nonsense", "interval_hours": 720}, timeout=10)
        assert r.status_code == 400

    def test_run_now_missing_returns_404(self, sess):
        r = sess.post(f"{BASE_URL}/api/schedules/nope-nope/run-now", timeout=10)
        assert r.status_code == 404

    def test_delete_missing_returns_404(self, sess):
        r = sess.delete(f"{BASE_URL}/api/schedules/nope-nope", timeout=10)
        assert r.status_code == 404


# ============================================================
# SIGMA SOURCES — validate parse_repo_url through create endpoint;
# DO NOT trigger sync-now against real GitHub.
# ============================================================
class TestSigmaSources:
    URL_SHAPES = [
        "SigmaHQ/sigma/rules-emerging-threats/2024/Malware",
        "SigmaHQ/sigma",
        "https://github.com/SigmaHQ/sigma",
        "https://github.com/SigmaHQ/sigma/tree/master/rules/threat-hunting",
    ]

    def test_create_various_url_shapes(self, sess):
        created_ids = []
        try:
            for i, url in enumerate(self.URL_SHAPES):
                r = sess.post(f"{BASE_URL}/api/sigma-sources",
                              json={"github_url": url,
                                    "name": f"TEST_sigsrc_{i}_{int(time.time())}",
                                    "enabled": False,   # keep disabled so scheduler won't fire
                                    "interval_hours": 720}, timeout=10)
                assert r.status_code == 200, f"{url} → {r.status_code} {r.text}"
                body = r.json()
                assert body["github_url"] == url
                assert body["enabled"] is False
                assert "_id" not in body
                created_ids.append(body["id"])

            # LIST
            lst = sess.get(f"{BASE_URL}/api/sigma-sources").json()
            for cid in created_ids:
                assert any(s["id"] == cid for s in lst)

            # PATCH toggle enabled on then off (keep off for cleanup)
            pid = created_ids[0]
            p1 = sess.patch(f"{BASE_URL}/api/sigma-sources/{pid}", json={"enabled": True})
            assert p1.status_code == 200 and p1.json()["enabled"] is True
            p2 = sess.patch(f"{BASE_URL}/api/sigma-sources/{pid}", json={"enabled": False})
            assert p2.status_code == 200 and p2.json()["enabled"] is False
        finally:
            for cid in created_ids:
                sess.delete(f"{BASE_URL}/api/sigma-sources/{cid}")

    def test_invalid_url_returns_400(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma-sources",
                      json={"github_url": "", "name": "empty"}, timeout=10)
        assert r.status_code == 400
        r2 = sess.post(f"{BASE_URL}/api/sigma-sources",
                      json={"github_url": "onlyoneslug", "name": "bad"}, timeout=10)
        assert r2.status_code == 400

    def test_invalid_scope(self, sess):
        r = sess.post(f"{BASE_URL}/api/sigma-sources",
                      json={"github_url": "SigmaHQ/sigma", "scope": "planet"}, timeout=10)
        assert r.status_code == 400


# ============================================================
# MARKETPLACE — info, rotate-key, public feed, signature
# ============================================================
def _sign(body_dict: dict, key_hex: str) -> str:
    canonical = json.dumps({k: v for k, v in body_dict.items() if k != "_signature"},
                           sort_keys=True).encode()
    sig = hmac.new(bytes.fromhex(key_hex), canonical, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


class TestMarketplaceInfoAndFeed:
    def test_info_and_rotate(self, sess):
        r = sess.get(f"{BASE_URL}/api/marketplace/info", timeout=10)
        assert r.status_code == 200, r.text
        info = r.json()
        for k in ("feed_id", "signing_key", "feed_url"):
            assert k in info and info[k]
        assert info["feed_url"].endswith(f"?fid={info['feed_id']}")

        old_key = info["signing_key"]
        rot = sess.post(f"{BASE_URL}/api/marketplace/rotate-key", timeout=10)
        assert rot.status_code == 200
        new_key = rot.json()["signing_key"]
        assert new_key and new_key != old_key

        # verify /info reflects the new key
        info2 = sess.get(f"{BASE_URL}/api/marketplace/info").json()
        assert info2["signing_key"] == new_key

    def test_public_feed_no_auth(self):
        # fetch info with auth to get feed_url; then hit feed without auth
        s = requests.Session()
        r = s.post(f"{BASE_URL}/api/auth/login",
                   json={"email": ADMIN_EMAIL, "password": ADMIN_PW}).json()
        info = requests.get(
            f"{BASE_URL}/api/marketplace/info",
            headers={"Authorization": f"Bearer {r['access_token']}"}).json()

        # No auth → still 200
        pub = requests.get(info["feed_url"], timeout=15)
        assert pub.status_code == 200, pub.text
        body = pub.json()
        assert "feed_id" in body and "count" in body and "templates" in body
        assert "_signature" in body
        assert pub.headers.get("X-SecMaster-Signature") == body["_signature"]
        assert body["feed_id"] == info["feed_id"]

        # signature must match HMAC over body-without-_signature using current signing_key
        expected = _sign(body, info["signing_key"])
        assert expected == body["_signature"], "server feed signature does not verify with reported signing_key"

    def test_feed_with_shared_template_count_gt_zero(self, sess):
        # Ensure at least one shared template exists
        # find any plugin, save as template shared=True
        plugs = sess.get(f"{BASE_URL}/api/plugins").json()
        assert plugs, "no plugins available to derive template from"
        pid = plugs[0]["id"]
        tname = f"TEST_mkt_shared_{int(time.time())}"
        rt = sess.post(f"{BASE_URL}/api/plugins/{pid}/save-as-template",
                       json={"name": tname, "shared": True})
        assert rt.status_code == 200, rt.text
        tpl_id = rt.json()["id"]
        try:
            info = sess.get(f"{BASE_URL}/api/marketplace/info").json()
            pub = requests.get(info["feed_url"], timeout=15).json()
            assert pub["count"] >= 1
            assert any(t["name"] == tname for t in pub["templates"])
        finally:
            sess.delete(f"{BASE_URL}/api/plugin-templates/{tpl_id}")


# ============================================================
# MARKETPLACE SUBSCRIPTIONS — loopback verify + import + cascade delete
# ============================================================
class TestMarketplaceSubscriptions:
    def test_subscription_verified_true_and_import_and_cascade(self, sess):
        info = sess.get(f"{BASE_URL}/api/marketplace/info").json()

        # Guarantee at least one shared template
        plugs = sess.get(f"{BASE_URL}/api/plugins").json()
        assert plugs
        pid = plugs[0]["id"]
        tname = f"TEST_mkt_sub_{int(time.time())}"
        rt = sess.post(f"{BASE_URL}/api/plugins/{pid}/save-as-template",
                       json={"name": tname, "shared": True})
        assert rt.status_code == 200
        tpl_id = rt.json()["id"]

        sub_id = None
        try:
            # Create subscription pointing at own feed with the correct signing key
            csub = sess.post(f"{BASE_URL}/api/marketplace/subscriptions", json={
                "name": f"TEST_selfsub_{int(time.time())}",
                "feed_url": info["feed_url"],
                "signing_key": info["signing_key"],
                "enabled": False,       # keep disabled so scheduler won't auto-run
                "interval_hours": 720,
            })
            assert csub.status_code == 200, csub.text
            sub = csub.json()
            sub_id = sub["id"]
            assert "_id" not in sub

            # sync-now → verified=true, imports > 0
            run = sess.post(f"{BASE_URL}/api/marketplace/subscriptions/{sub_id}/sync-now",
                            timeout=30)
            assert run.status_code == 200, run.text
            result = run.json()
            assert result["verified"] is True
            assert result["templates_seen"] >= 1
            # imported+updated should cover at least our shared tpl
            assert (result.get("imported", 0) + result.get("updated", 0)) >= 1

            # verify imported templates exist with subscription_id + read_only + source_url
            tpls = sess.get(f"{BASE_URL}/api/plugin-templates").json()
            imported = [t for t in tpls if t.get("subscription_id") == sub_id]
            assert imported, "no imported templates linked to subscription_id"
            for t in imported:
                assert t.get("read_only") is True
                assert t.get("source_url") == info["feed_url"]
                assert t.get("name", "").startswith(f"[{sub['name']}] ")

            # DELETE subscription should cascade-remove imported templates
            d = sess.delete(f"{BASE_URL}/api/marketplace/subscriptions/{sub_id}", timeout=10)
            assert d.status_code == 200
            sub_id = None  # avoid double-delete in finally

            tpls_after = sess.get(f"{BASE_URL}/api/plugin-templates").json()
            leftover = [t for t in tpls_after if t.get("subscription_id") == sub["id"]]
            assert not leftover, f"cascade delete failed: {leftover}"
        finally:
            # cleanup shared source template
            sess.delete(f"{BASE_URL}/api/plugin-templates/{tpl_id}")
            if sub_id:
                sess.delete(f"{BASE_URL}/api/marketplace/subscriptions/{sub_id}")

    def test_subscription_wrong_key_verified_false(self, sess):
        info = sess.get(f"{BASE_URL}/api/marketplace/info").json()
        wrong_key = "00" * 32  # valid hex, wrong value
        csub = sess.post(f"{BASE_URL}/api/marketplace/subscriptions", json={
            "name": f"TEST_wrongkey_{int(time.time())}",
            "feed_url": info["feed_url"],
            "signing_key": wrong_key,
            "enabled": False,
            "interval_hours": 720,
        })
        assert csub.status_code == 200
        sub_id = csub.json()["id"]
        try:
            run = sess.post(
                f"{BASE_URL}/api/marketplace/subscriptions/{sub_id}/sync-now",
                timeout=30)
            assert run.status_code == 200, run.text
            assert run.json()["verified"] is False
        finally:
            sess.delete(f"{BASE_URL}/api/marketplace/subscriptions/{sub_id}")

    def test_invalid_feed_url_400(self, sess):
        r = sess.post(f"{BASE_URL}/api/marketplace/subscriptions", json={
            "name": "bad", "feed_url": "not-a-url"}, timeout=10)
        assert r.status_code == 400


# ============================================================
# SIGNATURE INTEGRITY — repeat fetch, rotation invalidates old sig
# ============================================================
class TestSignatureIntegrity:
    def test_signature_stability_between_fetches(self):
        # Without auth (public endpoint). Fetch twice, no template changes in between.
        # Get feed_url via auth first
        s = requests.Session()
        tok = s.post(f"{BASE_URL}/api/auth/login",
                     json={"email": ADMIN_EMAIL, "password": ADMIN_PW}).json()["access_token"]
        info = requests.get(f"{BASE_URL}/api/marketplace/info",
                            headers={"Authorization": f"Bearer {tok}"}).json()

        r1 = requests.get(info["feed_url"], timeout=10).json()
        time.sleep(0.5)
        r2 = requests.get(info["feed_url"], timeout=10).json()
        # Both signatures must at minimum verify with current signing_key.
        assert _sign(r1, info["signing_key"]) == r1["_signature"]
        assert _sign(r2, info["signing_key"]) == r2["_signature"]
        # Spec requires "same signature until templates change"
        # NOTE: build_feed includes generated_at which will differ between fetches;
        # this assertion documents the expected behaviour.
        assert r1["_signature"] == r2["_signature"], (
            "Signatures differ across identical fetches — likely because "
            "generated_at is included in the signed body (build_feed in marketplace.py)."
        )

    def test_rotate_invalidates_old_signature(self, sess):
        info = sess.get(f"{BASE_URL}/api/marketplace/info").json()
        old_key = info["signing_key"]

        feed = requests.get(info["feed_url"], timeout=10).json()
        old_sig = feed["_signature"]
        # Sanity: old sig verifies with old key
        assert _sign(feed, old_key) == old_sig

        # Rotate
        sess.post(f"{BASE_URL}/api/marketplace/rotate-key")
        info2 = sess.get(f"{BASE_URL}/api/marketplace/info").json()
        new_key = info2["signing_key"]
        assert new_key != old_key

        # Old sig should NOT verify with new key
        assert _sign(feed, new_key) != old_sig


# ============================================================
# REGRESSION — verify existing endpoints still coexist
# ============================================================
class TestRegressionCoexist:
    def test_health(self, sess):
        r = sess.get(f"{BASE_URL}/api/health", timeout=10)
        assert r.status_code == 200 and r.json()["status"] == "ok"

    def test_fleet_and_plugins(self, sess):
        assert sess.get(f"{BASE_URL}/api/workstations").status_code == 200
        assert sess.get(f"{BASE_URL}/api/plugins").status_code == 200

    def test_ioc_and_sigma_preview(self, sess):
        # existing ioc endpoint still reachable via a workstation
        ws = sess.get(f"{BASE_URL}/api/workstations").json()[0]
        r = sess.get(f"{BASE_URL}/api/workstations/{ws['id']}/ioc")
        assert r.status_code == 200
        # sigma preview endpoint still works
        rp = sess.post(f"{BASE_URL}/api/sigma/preview",
                       json={"sigma_yaml": "title: X\ndetection:\n  s:\n    Hashes|contains:\n      - 'md5=44d88612fea8a8f36de82e1278abb02f'\n  condition: s\n"})
        assert rp.status_code == 200

    def test_bulk_sweep_still_works(self, sess):
        r = sess.post(f"{BASE_URL}/api/ioc/bulk-sweep",
                      json={"scope": "online"}, timeout=60)
        # 200 or 400 (if no query provider) — either indicates endpoint intact
        assert r.status_code in (200, 400)
