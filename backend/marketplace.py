"""Team Template Marketplace — sign a feed of shared templates, subscribe to remote feeds.

- Local dashboard exposes GET /api/marketplace/feed (public JSON, HMAC-SHA256 signed).
- Each dashboard has a randomly generated 32-byte signing key + a stable feed_id.
- Remote dashboards can subscribe by URL (+ optional shared signing key for verification).
- Subscribed templates are stored in the local `plugin_templates` collection with:
    subscription_id, source_url, verified (bool), read_only=True.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone

import httpx

log = logging.getLogger("secmaster.marketplace")

FEED_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def get_or_create_config(db) -> dict:
    cfg = await db.marketplace_config.find_one({"id": "singleton"})
    if cfg:
        return cfg
    cfg = {
        "id": "singleton",
        "feed_id": secrets.token_urlsafe(12),
        "signing_key": secrets.token_hex(32),
        "created_at": _now(),
    }
    await db.marketplace_config.insert_one(cfg)
    return cfg


async def rotate_signing_key(db) -> dict:
    cfg = await get_or_create_config(db)
    new_key = secrets.token_hex(32)
    await db.marketplace_config.update_one({"id": "singleton"}, {"$set": {"signing_key": new_key, "rotated_at": _now()}})
    cfg["signing_key"] = new_key
    return cfg


def _sign(body: bytes, key_hex: str) -> str:
    sig = hmac.new(bytes.fromhex(key_hex), body, hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


def _canonicalize_template(t: dict) -> dict:
    """Strip Mongo internals + include only fields safe to publish.

    IMPORTANT: never publish `secrets_encrypted` even though it's encrypted —
    the key is local to this dashboard so it'd be worthless elsewhere anyway.
    """
    return {
        "name": t.get("name"),
        "type": t.get("type"),
        "config": t.get("config") or {},
        "event_subscriptions": t.get("event_subscriptions") or [],
        "shared": True,
        "source_created_by": t.get("created_by"),
        "source_created_at": t.get("created_at"),
    }


async def build_feed(db) -> tuple[dict, str]:
    cfg = await get_or_create_config(db)
    templates_raw = await db.plugin_templates.find({"shared": True}).sort("created_at", -1).to_list(500)
    templates = [_canonicalize_template(t) for t in templates_raw]
    body = {
        "feed_version": FEED_VERSION,
        "feed_id": cfg["feed_id"],
        "generated_at": _now(),
        "count": len(templates),
        "templates": templates,
    }
    body_bytes = json.dumps(body, sort_keys=True).encode()
    signature = _sign(body_bytes, cfg["signing_key"])
    return body, signature


async def verify_and_import_subscription(db, sub: dict) -> dict:
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await client.get(sub["feed_url"])
        r.raise_for_status()
        body_bytes = r.content
        body = json.loads(body_bytes)
        provided_sig = r.headers.get("X-SecMaster-Signature") or body.get("_signature")

    verified = False
    if sub.get("signing_key") and provided_sig:
        # rebuild canonical bytes (in case remote sent with headers we ignored)
        candidate_bytes = json.dumps({k: v for k, v in body.items() if k != "_signature"}, sort_keys=True).encode()
        expected = _sign(candidate_bytes, sub["signing_key"])
        verified = hmac.compare_digest(expected, provided_sig)

    imported = 0
    updated = 0
    for tpl in body.get("templates", []):
        prefixed_name = f"[{sub['name']}] {tpl.get('name')}"
        doc = {
            "id": secrets.token_hex(10),
            "name": prefixed_name,
            "type": tpl.get("type"),
            "config": tpl.get("config") or {},
            "event_subscriptions": tpl.get("event_subscriptions") or [],
            "secrets_encrypted": {},
            "created_at": _now(),
            "created_by": f"marketplace:{sub['name']}",
            "shared": False,
            "subscription_id": sub["id"],
            "source_url": sub["feed_url"],
            "verified": verified,
            "read_only": True,
        }
        existing = await db.plugin_templates.find_one({
            "subscription_id": sub["id"],
            "name": prefixed_name,
        })
        if existing:
            await db.plugin_templates.update_one({"_id": existing["_id"]}, {"$set": {
                "config": doc["config"],
                "event_subscriptions": doc["event_subscriptions"],
                "verified": verified,
            }})
            updated += 1
        else:
            await db.plugin_templates.insert_one(doc)
            imported += 1

    return {
        "feed_id": body.get("feed_id"),
        "templates_seen": len(body.get("templates", [])),
        "imported": imported,
        "updated": updated,
        "verified": verified,
    }
