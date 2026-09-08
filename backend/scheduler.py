"""Background async scheduler for periodic jobs.

Runs a single asyncio task on startup that ticks every 60s. Each tick:
- fires eligible bulk-sweep schedules (`db.schedules`)
- fires eligible sigma-repo syncs (`db.sigma_sources`)
- fires eligible marketplace subscription pulls (`db.marketplace_subscriptions`)

Job docs share the same `enabled`, `interval_hours`, `last_run_at` shape so the
"due" logic is a single function.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Callable, Awaitable

log = logging.getLogger("secmaster.scheduler")

TICK_INTERVAL_S = 60


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _due(job: dict) -> bool:
    if not job.get("enabled"):
        return False
    hours = int(job.get("interval_hours") or 24)
    last = job.get("last_run_at")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except ValueError:
        return True
    return _now() >= last_dt + timedelta(hours=hours)


async def run_scheduler(
    db,
    run_bulk_sweep: Callable[[dict], Awaitable[dict]],
    run_sigma_sync: Callable[[dict], Awaitable[dict]],
    run_marketplace_sync: Callable[[dict], Awaitable[dict]],
) -> None:
    log.info("scheduler starting · tick=%ds", TICK_INTERVAL_S)
    # small initial delay so startup finishes cleanly
    await asyncio.sleep(10)
    while True:
        try:
            await _tick(db, "schedules", run_bulk_sweep)
            await _tick(db, "sigma_sources", run_sigma_sync)
            await _tick(db, "marketplace_subscriptions", run_marketplace_sync)
        except Exception as e:
            log.warning("scheduler tick failed: %s", e)
        await asyncio.sleep(TICK_INTERVAL_S)


async def _tick(db, collection: str, handler: Callable[[dict], Awaitable[dict]]) -> None:
    async for job in db[collection].find({"enabled": True}):
        if not _due(job):
            continue
        started = _now().isoformat()
        await db[collection].update_one({"id": job["id"]}, {"$set": {"last_started_at": started}})
        try:
            result = await handler(job)
            await db[collection].update_one({"id": job["id"]}, {"$set": {
                "last_run_at": _now().isoformat(),
                "last_run_status": "ok",
                "last_run_meta": result,
            }})
        except Exception as e:
            log.warning("job %s (%s) failed: %s", job.get("id"), collection, e)
            await db[collection].update_one({"id": job["id"]}, {"$set": {
                "last_run_at": _now().isoformat(),
                "last_run_status": "error",
                "last_run_meta": {"error": f"{e.__class__.__name__}: {e}"[:400]},
            }})
