"""Fleet status engine — derive online/drift/offline from real heartbeat data."""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from datetime import datetime, timezone

log = logging.getLogger("secmaster.status")

OFFLINE_AFTER_S = int(os.environ["OFFLINE_AFTER_SECONDS"])
LOOP_INTERVAL_S = 30


def compute_status(ws: dict, now: datetime | None = None) -> str:
    if ws.get("demo"):
        return ws.get("status", "online")
    now = now or datetime.now(timezone.utc)
    hb = ws.get("last_heartbeat")
    if not hb:
        return "offline"
    try:
        age = (now - datetime.fromisoformat(hb)).total_seconds()
    except ValueError:
        return "offline"
    if age > OFFLINE_AFTER_S:
        return "offline"
    desired = ws.get("desired_profile")
    if desired and desired != ws.get("profile"):
        return "drift"
    return "online"


async def recompute_all(db) -> int:
    now = datetime.now(timezone.utc)
    changed = 0
    async for ws in db.workstations.find({"demo": {"$ne": True}}):
        new = compute_status(ws, now)
        if new == ws.get("status"):
            continue
        await db.workstations.update_one({"id": ws["id"]}, {"$set": {"status": new}})
        changed += 1
        if new == "offline":
            await db.audit.insert_one({
                "id": secrets.token_hex(8), "workstation_id": ws["id"], "hostname": ws.get("hostname"),
                "kind": "heartbeat", "message": f"Agent went offline (no heartbeat for >{OFFLINE_AFTER_S}s)",
                "at": now.isoformat(), "meta": {"previous": ws.get("status")},
            })
    return changed


async def status_loop(db) -> None:
    await asyncio.sleep(5)
    while True:
        try:
            n = await recompute_all(db)
            if n:
                log.info("status recompute: %d workstation(s) changed", n)
        except Exception as e:
            log.warning("status loop failed: %s", e)
        await asyncio.sleep(LOOP_INTERVAL_S)
