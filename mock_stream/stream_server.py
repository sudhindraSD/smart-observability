"""Slice 2 mock telemetry stream: two simulated customer sites in real time.

Box 0 of the demo. Emits valid ``InternalRawEvent`` JSON (1 event/sec per
source) over both a WebSocket stream and an HTTP poll endpoint, plus chaos
injector endpoints for every live judge scenario. This module plays the part
of the customer estate; it never touches the collector's database.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from typing import AsyncIterator, Deque, Dict, List, Set
from uuid import uuid4

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

from shared.contracts import (
    ConnectivityState,
    InternalRawEvent,
    Metrics,
    SourceType,
    parse_utc_iso,
    utc_now_iso,
)
from shared.safe_errors import install_safe_validation_handler

TICK_SECONDS = 1.0
SPIKE_DURATION_SEC = 20.0
CASCADE_DOWNSTREAM_DELAY_SEC = 1.5
POLL_BUFFER_MAX = 500

SECRET_LOG_LINE = (
    "payment callback trace: Authorization: Bearer sk_live_98a7sd98a7sd "
    "password=hunter2xyz client_ip=10.20.4.15 result=declined"
)


@dataclass
class SourceProfile:
    """Baseline metric template for one simulated source."""

    real_hostname: str
    source_type: SourceType
    upstream_device_real_name: str | None = None


@dataclass
class SiteConfig:
    site: str
    source_timezone: str
    sources: List[SourceProfile] = field(default_factory=list)
    buffer: Deque[dict] = field(default_factory=lambda: deque(maxlen=POLL_BUFFER_MAX))
    ws_queues: Set[asyncio.Queue] = field(default_factory=set)
    overrides: Dict[str, dict] = field(default_factory=dict)

    def downstream_servers(self) -> List[str]:
        return [
            s.real_hostname for s in self.sources if s.source_type == SourceType.SERVER
        ]


SITES: Dict[str, SiteConfig] = {
    "bank-a": SiteConfig(
        site="bank-a",
        source_timezone="Asia/Kolkata",
        sources=[
            SourceProfile("core-rtr-blr-01", SourceType.NETWORK_DEVICE),
            SourceProfile(
                "pay-db-01.internal",
                SourceType.SERVER,
                upstream_device_real_name="core-rtr-blr-01",
            ),
            SourceProfile(
                "pay-api-02.internal",
                SourceType.SERVER,
                upstream_device_real_name="core-rtr-blr-01",
            ),
        ],
    ),
    "hospital-b": SiteConfig(
        site="hospital-b",
        source_timezone="Europe/Berlin",
        sources=[
            SourceProfile("edge-rtr-fra-01", SourceType.NETWORK_DEVICE),
            SourceProfile(
                "ehr-app-01.internal",
                SourceType.SERVER,
                upstream_device_real_name="edge-rtr-fra-01",
            ),
        ],
    ),
}

SCENARIOS = (
    "secret",
    "failed_logins",
    "latency_spike",
    "cpu_anomaly",
    "cascade_incident",
    "duplicate_payload",
    "out_of_order",
)


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------


def _jitter(base: float, spread: float) -> float:
    return round(random.uniform(base - spread, base + spread), 3)


def _active_override(cfg: SiteConfig, source_name: str) -> dict:
    ov = cfg.overrides.get(source_name)
    if not ov:
        return {}
    if ov["until"] <= time.monotonic():
        cfg.overrides.pop(source_name, None)
        return {}
    return ov["metrics"]


def _router_metrics(cfg: SiteConfig, name: str) -> Metrics:
    ov = _active_override(cfg, name)
    latency = max(0.0, ov.get("latency_ms", _jitter(12.0, 4.0)))
    loss = min(100.0, max(0.0, ov.get("packet_loss_pct", _jitter(0.1, 0.08))))
    return Metrics(
        bandwidth_mbps=_jitter(940.0, 25.0),
        latency_ms=latency,
        packet_loss_pct=loss,
        connectivity=ov.get(
            "connectivity",
            ConnectivityState.UP if latency < 150.0 else ConnectivityState.DEGRADED,
        ),
    )


def _server_metrics(cfg: SiteConfig, name: str) -> Metrics:
    ov = _active_override(cfg, name)
    return Metrics(
        cpu_pct=min(100.0, max(0.0, ov.get("cpu_pct", _jitter(30.0, 6.0)))),
        memory_pct=min(100.0, max(0.0, ov.get("memory_pct", _jitter(55.0, 6.0)))),
        disk_pct=min(100.0, max(0.0, ov.get("disk_pct", _jitter(60.0, 4.0)))),
        service_up=True,
        latency_ms=max(0.0, ov.get("latency_ms", _jitter(8.0, 3.0))),
        connectivity=ov.get("connectivity", ConnectivityState.UP),
    )


def _profile(cfg: SiteConfig, name: str) -> SourceProfile:
    return next(p for p in cfg.sources if p.real_hostname == name)


def build_event(cfg: SiteConfig, profile: SourceProfile) -> InternalRawEvent:
    return InternalRawEvent(
        event_time_utc=utc_now_iso(),
        source_timezone=cfg.source_timezone,
        real_hostname=profile.real_hostname,
        source_type=profile.source_type,
        upstream_device_real_name=profile.upstream_device_real_name,
        metrics=(
            _router_metrics(cfg, profile.real_hostname)
            if profile.source_type == SourceType.NETWORK_DEVICE
            else _server_metrics(cfg, profile.real_hostname)
        ),
    )


def emit(cfg: SiteConfig, event: InternalRawEvent) -> dict:
    """Fan one event out to the poll buffer and every live WebSocket client."""
    payload = event.model_dump(mode="json")
    cfg.buffer.append(payload)
    for queue in list(cfg.ws_queues):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            pass
    return payload


def _emit_many(cfg: SiteConfig, events: List[InternalRawEvent]) -> List[dict]:
    return [emit(cfg, ev) for ev in events]


def _set_override(
    cfg: SiteConfig, source: str, metrics: dict, duration_sec: float
) -> None:
    cfg.overrides[source] = {
        "metrics": metrics,
        "until": time.monotonic() + duration_sec,
    }


# ---------------------------------------------------------------------------
# Background 1 Hz tickers
# ---------------------------------------------------------------------------


async def _site_ticker(site: str) -> None:
    cfg = SITES[site]
    while True:
        for profile in cfg.sources:
            emit(cfg, build_event(cfg, profile))
        await asyncio.sleep(TICK_SECONDS)


_ticker_tasks: List[asyncio.Task] = []


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    if not _ticker_tasks:
        _ticker_tasks.extend(
            asyncio.create_task(_site_ticker(site)) for site in SITES
        )
    try:
        yield
    finally:
        for task in _ticker_tasks:
            task.cancel()
        _ticker_tasks.clear()


app = FastAPI(title="Mock Chaos Stream", version="2.0.0", lifespan=lifespan)
install_safe_validation_handler(app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Streams
# ---------------------------------------------------------------------------


@app.websocket("/ws/stream/{site}")
async def ws_stream(websocket: WebSocket, site: str) -> None:
    if site not in SITES:
        await websocket.close(code=4404)
        return
    cfg = SITES[site]
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue(maxsize=POLL_BUFFER_MAX)
    cfg.ws_queues.add(queue)
    try:
        while True:
            item = await queue.get()
            if isinstance(item, dict):
                await websocket.send_json(item)
            else:
                await websocket.send_text(item)
    except WebSocketDisconnect:
        pass
    finally:
        cfg.ws_queues.discard(queue)


@app.get("/api/poll/{site}")
async def poll_site(site: str) -> dict:
    if site not in SITES:
        return JSONResponse(status_code=404, content={"error": f"unknown site {site}"})
    cfg = SITES[site]
    events: List[dict] = []
    while cfg.buffer:
        events.append(cfg.buffer.popleft())
    return {"site": site, "count": len(events), "events": events}


# ---------------------------------------------------------------------------
# Chaos injector
# ---------------------------------------------------------------------------


@app.post("/chaos/{scenario}")
async def chaos(scenario: str, site: str = "bank-a") -> dict:
    if site not in SITES:
        return JSONResponse(status_code=404, content={"error": f"unknown site {site}"})
    if scenario not in SCENARIOS:
        return JSONResponse(
            status_code=404,
            content={
                "error": f"unknown scenario {scenario}",
                "scenarios": list(SCENARIOS),
            },
        )
    cfg = SITES[site]
    router = next(p for p in cfg.sources if p.source_type == SourceType.NETWORK_DEVICE)
    servers = cfg.downstream_servers()

    if scenario == "secret":
        target = servers[0]
        event = build_event(cfg, _profile(cfg, target))
        event.raw_log_line = SECRET_LOG_LINE
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": "raw log carrying a live secret, plaintext password and private IP emitted",
            "emitted": _emit_many(cfg, [event]),
        }

    if scenario == "failed_logins":
        target = servers[0]
        profile = _profile(cfg, target)
        burst: List[InternalRawEvent] = []
        for i in range(14):
            ev = build_event(cfg, profile)
            ev.failed_login_event = True
            ev.raw_log_line = (
                f"Failed password for invalid user oracle from 10.20.4.{15 + i} "
                f"port {47000 + i} ssh2"
            )
            burst.append(ev)
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": f"burst of 14 failed-login events emitted for {target}",
            "emitted": _emit_many(cfg, burst),
        }

    if scenario == "latency_spike":
        _set_override(
            cfg,
            router.real_hostname,
            {
                "latency_ms": 185.0,
                "packet_loss_pct": 4.2,
                "connectivity": ConnectivityState.DEGRADED,
            },
            SPIKE_DURATION_SEC,
        )
        event = build_event(cfg, router)
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": (
                f"router {router.real_hostname} latency ~185ms / packet loss ~4.2% "
                f"for {SPIKE_DURATION_SEC:.0f}s"
            ),
            "emitted": _emit_many(cfg, [event]),
        }

    if scenario == "cpu_anomaly":
        events: List[InternalRawEvent] = []
        for name in servers:
            _set_override(
                cfg, name, {"cpu_pct": 92.0, "memory_pct": 88.0}, SPIKE_DURATION_SEC
            )
            events.append(build_event(cfg, _profile(cfg, name)))
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": (
                f"CPU ~92% / memory ~88% on {', '.join(servers)} "
                f"for {SPIKE_DURATION_SEC:.0f}s"
            ),
            "emitted": _emit_many(cfg, events),
        }

    if scenario == "cascade_incident":
        _set_override(
            cfg,
            router.real_hostname,
            {
                "latency_ms": 190.0,
                "packet_loss_pct": 4.5,
                "connectivity": ConnectivityState.DEGRADED,
            },
            CASCADE_DOWNSTREAM_DELAY_SEC + SPIKE_DURATION_SEC,
        )
        router_event = build_event(cfg, router)
        asyncio.create_task(_cascade_downstream(cfg, servers))
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": (
                f"router {router.real_hostname} degraded now; downstream "
                f"{', '.join(servers)} spikes in {CASCADE_DOWNSTREAM_DELAY_SEC}s"
            ),
            "emitted": _emit_many(cfg, [router_event]),
            "downstream_scheduled_in_sec": CASCADE_DOWNSTREAM_DELAY_SEC,
            "downstream_sources": servers,
        }

    if scenario == "duplicate_payload":
        profile = _profile(cfg, servers[0])
        forced_id = f"forced-dup-{uuid4().hex[:12]}"
        first = build_event(cfg, profile)
        first.forced_payload_id = forced_id
        second = build_event(cfg, profile)
        second.forced_payload_id = forced_id
        return {
            "status": "ok",
            "scenario": scenario,
            "site": site,
            "detail": f"two events emitted sharing forced_payload_id {forced_id}",
            "forced_payload_id": forced_id,
            "emitted": _emit_many(cfg, [first, second]),
        }

    # out_of_order
    profile = _profile(cfg, servers[0])
    event = build_event(cfg, profile)
    event.event_time_utc = (
        (parse_utc_iso(utc_now_iso()) - timedelta(seconds=90))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    event.metrics.latency_ms = 180.0
    return {
        "status": "ok",
        "scenario": scenario,
        "site": site,
        "detail": "event emitted with event_time_utc 90 seconds in the past and elevated latency",
        "emitted": _emit_many(cfg, [event]),
    }


async def _cascade_downstream(cfg: SiteConfig, servers: List[str]) -> None:
    """Phase 2 of the cascade: 1.5s after the router spike, degrade the
    downstream servers so Box 2 correlates everything into one incident."""
    await asyncio.sleep(CASCADE_DOWNSTREAM_DELAY_SEC)
    for name in servers:
        _set_override(
            cfg,
            name,
            {"cpu_pct": 92.0, "memory_pct": 88.0, "latency_ms": 120.0},
            SPIKE_DURATION_SEC,
        )
        event = build_event(cfg, _profile(cfg, name))
        event.raw_log_line = (
            f"upstream router unreachable from {name}: connection timed out "
            "after 3 retries; error rate climbing on app callbacks"
        )
        emit(cfg, event)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=9000)
