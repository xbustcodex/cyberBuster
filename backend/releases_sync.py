"""GitHub Releases sync — real release stream with cosign/sigstore asset detection."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import httpx

log = logging.getLogger("secmaster.releases")

GITHUB_API = "https://api.github.com"
SIG_SUFFIXES = (".sig", ".bundle", ".sigstore", ".sigstore.json", ".pem", ".intoto.jsonl", ".asc")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def repo_name() -> str:
    return os.environ["GITHUB_RELEASES_REPO"].strip().strip("/")


async def sync_releases(db) -> dict:
    repo = repo_name()
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "security-master-dashboard"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    await db.meta.update_one({"key": "releases_sync"}, {"$set": {"status": "running", "started_at": _now(), "repo": repo}}, upsert=True)
    try:
        async with httpx.AsyncClient(timeout=20.0, headers=headers) as c:
            r = await c.get(f"{GITHUB_API}/repos/{repo}/releases", params={"per_page": 30})
            r.raise_for_status()
            docs: list[dict] = []
            for rel in r.json():
                if rel.get("draft"):
                    continue
                tag = rel["tag_name"]
                sha = ""
                cr = await c.get(f"{GITHUB_API}/repos/{repo}/commits/{tag}")
                if cr.status_code == 200:
                    sha = cr.json().get("sha", "")
                assets = [{
                    "name": a["name"], "size": a.get("size", 0),
                    "download_url": a.get("browser_download_url"),
                } for a in rel.get("assets") or []]
                sig_assets = [a["name"] for a in assets if a["name"].lower().endswith(SIG_SUFFIXES)]
                channel = "beta" if rel.get("prerelease") else ("nightly" if "nightly" in tag.lower() else "stable")
                docs.append({
                    "id": f"gh-{rel['id']}",
                    "version": tag,
                    "name": rel.get("name") or tag,
                    "commit_sha": sha,
                    "signature_status": "signed" if sig_assets else "unsigned",
                    "signature_assets": sig_assets,
                    "signer": (rel.get("author") or {}).get("login") or "unknown",
                    "published_at": rel.get("published_at") or rel.get("created_at"),
                    "changelog": (rel.get("body") or "")[:2000],
                    "channel": channel,
                    "assets": assets,
                    "html_url": rel.get("html_url"),
                    "source": "github",
                    "repo": repo,
                })
        await db.releases.delete_many({"source": "github"})
        if docs:
            await db.releases.insert_many([dict(d) for d in docs])
        result = {"repo": repo, "releases": len(docs), "signed": sum(1 for d in docs if d["signature_status"] == "signed")}
        await db.meta.update_one({"key": "releases_sync"}, {"$set": {"status": "ok", "finished_at": _now(), "result": result, "error": None}})
        log.info("releases sync: %s", result)
        return result
    except Exception as e:
        await db.meta.update_one({"key": "releases_sync"}, {"$set": {
            "status": "error", "finished_at": _now(), "error": f"{e.__class__.__name__}: {e}"[:400],
        }})
        raise
