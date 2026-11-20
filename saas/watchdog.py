"""Slice 3 watchdog: offline-collector and stale-source detection.

Runs every 5 seconds against every regional DB. ``run_watchdog_pass`` is
directly callable with an injected ``now_utc`` so tests are deterministic
(no 50-second sleeps). Only downgrades are issued here; recovery happens
when fresh telemetry or a heartbeat arrives.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable, List, Optional

from saas.db import REGION_DB_FILES, SaasDatabase
from shared.contracts import parse_utc_iso, utc_now_iso

logger = logging.getLogger(__name__)

_WATCHDOG_INTERVAL_SEC = 5.0

_SOURCE_RANK = {"Excellent": 0, "Good": 1, "Fair": 2, "Poor": 3, "Unknown": -1}


class Watchdog:
    def __init__(
        self,
        db: SaasDatabase,
        cfg_provider: Callable[[str], Awaitable],
        interval_sec: float = _WATCHDOG_INTERVAL_SEC,
        on_change: Optional[Callable[[List[dict]], Awaitable[None]]] = None,
    ) -> None:
        self._db = db
        self._cfg_provider = cfg_provider
        self._interval = interval_sec
        self._on_change = on_change
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def run_watchdog_pass(self, now_utc: Optional[str] = None) -> List[dict]:
        """One deterministic pass over every regional DB.

        Returns a list of ``{"tenant_id", "frame"}`` broadcasts for every
        state change so the caller can push them to tenant WebSockets.
        """
        if now_utc:
            now_iso = now_utc
            now = parse_utc_iso(now_utc)
        else:
            now_iso = utc_now_iso()
            now = parse_utc_iso(now_iso)
        frames: List[dict] = []
        for region in REGION_DB_FILES:
            collectors = await self._db.list_collectors(region)
            for collector in collectors:
                frames.extend(
                    await self._check_collector(region, collector, now, now_iso)
                )
        return frames

    async def _check_collector(self, region: str, collector: dict, now, now_iso: str) -> List[dict]:
        tenant_id = collector["tenant_id"]
        collector_id = collector["collector_id"]
        cfg = await self._cfg_provider(tenant_id)
        frames: List[dict] = []

        heartbeat_age: Optional[float] = None
        if collector.get("last_heartbeat_utc"):
            try:
                heartbeat_age = (
                    now - parse_utc_iso(collector["last_heartbeat_utc"])
                ).total_seconds()
            except (TypeError, ValueError):
                heartbeat_age = None

        offline = (
            heartbeat_age is not None
            and heartbeat_age >= cfg.collector_offline_sec
        )
        if offline:
            if collector.get("health_state") != "Poor":
                await self._db.set_collector_offline(region, collector_id, now_iso)
                transition = await self._db.record_transition(
                    region,
                    tenant_id=tenant_id,
                    entity_id=collector_id,
                    entity_type="collector",
                    old_state=collector.get("health_state"),
                    new_state="Poor",
                    reason="Collector heartbeat timeout",
                    transition_time_utc=now_iso,
                )
                frames.append({"tenant_id": tenant_id, "frame": {"type": "transition", "data": transition}})
                frames.append({
                    "tenant_id": tenant_id,
                    "frame": {
                        "type": "collector",
                        "data": {
                            "collector_id": collector_id,
                            "tenant_id": tenant_id,
                            "region": region,
                            "health_state": "Poor",
                            "offline_detected_utc": now_iso,
                        },
                    },
                })
            frames.extend(
                await self._downgrade_sources(
                    region,
                    tenant_id,
                    collector_id,
                    [row for row in await self._db.list_sources_state(region, tenant_id)],
                    "Poor",
                    "Stale data: collector unreachable",
                    now_iso,
                )
            )
            return frames

        # Collector online: staleness ladder for its sources.
        sources = [
            row
            for row in await self._db.list_sources_state(region, tenant_id)
            if row.get("collector_id") == collector_id
        ]
        for source in sources:
            target = self._stale_target(source, now, cfg)
            if target is None:
                continue
            if _SOURCE_RANK.get(target, -1) <= _SOURCE_RANK.get(
                source.get("health_state") or "Unknown", -1
            ):
                continue
            await self._db.set_source_health(region, tenant_id, source["source_id"], target)
            transition = await self._db.record_transition(
                region,
                tenant_id=tenant_id,
                entity_id=source["source_id"],
                entity_type="source",
                old_state=source.get("health_state"),
                new_state=target,
                reason="Stale data: no telemetry within freshness window",
                transition_time_utc=now_iso,
            )
            frames.append({"tenant_id": tenant_id, "frame": {"type": "transition", "data": transition}})
        return frames

    def _stale_target(self, source: dict, now, cfg) -> Optional[str]:
        if source.get("last_ingested_utc"):
            try:
                age = (now - parse_utc_iso(source["last_ingested_utc"])).total_seconds()
            except (TypeError, ValueError):
                return None
            if age >= cfg.source_stale_poor_sec:
                return "Poor"
            if age >= cfg.source_stale_fair_sec:
                return "Fair"
        return None

    async def _downgrade_sources(
        self,
        region: str,
        tenant_id: str,
        collector_id: str,
        sources: List[dict],
        new_state: str,
        reason: str,
        now_iso: str,
    ) -> List[dict]:
        frames: List[dict] = []
        for source in sources:
            if source.get("collector_id") != collector_id:
                continue
            if source.get("health_state") == new_state:
                continue
            await self._db.set_source_health(region, tenant_id, source["source_id"], new_state)
            transition = await self._db.record_transition(
                region,
                tenant_id=tenant_id,
                entity_id=source["source_id"],
                entity_type="source",
                old_state=source.get("health_state"),
                new_state=new_state,
                reason=reason,
                transition_time_utc=now_iso,
            )
            frames.append({"tenant_id": tenant_id, "frame": {"type": "transition", "data": transition}})
        return frames

    # -- background loop -----------------------------------------------------------------

    async def start(self) -> None:
        self._stopping = asyncio.Event()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                frames = await self.run_watchdog_pass()
                if frames and self._on_change is not None:
                    await self._on_change(frames)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("watchdog pass failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=self._interval)
            except asyncio.TimeoutError:
                continue
