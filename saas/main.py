"""Slice 3 Box 2: central multi-tenant SaaS control plane.

FastAPI app over three physically separate SQLite WAL databases (one control
plane + one per region). Collectors authenticate with the seeded static token
registry; dashboard users authenticate with HS256 JWTs. ``tenant_id`` and
``region`` are ALWAYS taken from the verified credential — never from query
parameters or payload fields alone.
"""

from __future__ import annotations

import json
import math
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Set

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from saas.aiops import AiopsEngine, incident_row_to_record
from saas.auth import (
    DEMO_USERS,
    CollectorIdentity,
    TenantIdentity,
    authenticate_demo_user,
    get_current_tenant,
    issue_tenant_jwt,
    verify_collector,
    verify_ws_token,
)
from saas.db import REGION_DB_FILES, SaasDatabase
from saas.remediation import approve_remediation, rollback_remediation
from saas.watchdog import Watchdog
from shared.contracts import (
    CollectorHeartbeat,
    EgressMetadataPayload,
    HealthState,
    IngestBatchRequest,
    StrictBaseModel,
    ThresholdConfig,
    utc_now_iso,
)
from shared.safe_errors import install_safe_validation_handler


class LoginRequest(StrictBaseModel):
    username: str
    password: str


class TenantWsManager:
    """Per-tenant WebSocket connections receiving typed JSON frames."""

    def __init__(self) -> None:
        self._connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, tenant_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(tenant_id, set()).add(websocket)

    async def disconnect(self, tenant_id: str, websocket: WebSocket) -> None:
        connections = self._connections.get(tenant_id)
        if connections is not None:
            connections.discard(websocket)
            if not connections:
                self._connections.pop(tenant_id, None)

    async def broadcast(self, tenant_id: str, frame: Dict[str, Any]) -> None:
        payload = json.dumps(frame, default=str)
        for websocket in list(self._connections.get(tenant_id, ())):
            try:
                await websocket.send_text(payload)
            except Exception:
                await self.disconnect(tenant_id, websocket)


class SaasRuntime:
    """Wired-together database, AIOps engine, watchdog and WS broadcaster."""

    def __init__(self, data_dir: Optional[str] = None, disable_watchdog: bool = False) -> None:
        self.db = SaasDatabase(data_dir)
        self.ws = TenantWsManager()
        self.engine = AiopsEngine(self.db)
        self.disable_watchdog = disable_watchdog
        self.watchdog = Watchdog(self.db, self.cfg_for, on_change=self._broadcast_frames)

    async def cfg_for(self, tenant_id: str) -> ThresholdConfig:
        row = await self.db.get_threshold_config(tenant_id)
        if row and row.get("config_json"):
            try:
                return ThresholdConfig.model_validate_json(row["config_json"])
            except ValidationError:
                pass
        return ThresholdConfig()

    async def _broadcast_frames(self, frames: List[dict]) -> None:
        for item in frames:
            await self.ws.broadcast(item["tenant_id"], item["frame"])

    async def broadcast(self, tenant_id: str, frame_type: str, data: Any) -> None:
        await self.ws.broadcast(tenant_id, {"type": frame_type, "data": data})


def _seed_tenants() -> List[dict]:
    return [
        {
            "tenant_id": identity.tenant_id,
            "region": identity.region,
            "display_name": identity.tenant_id,
        }
        for identity in DEMO_USERS.values()
    ]


def _p95(values: List[float]) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(math.ceil(0.95 * len(ordered)) - 1, len(ordered) - 1))
    return ordered[index]


def _require_region(region: str) -> None:
    if region not in REGION_DB_FILES:
        raise HTTPException(status_code=404, detail=f"unknown region: {region}")


def _telemetry_frame_data(payload: EgressMetadataPayload, health_value: str) -> dict:
    return {
        "payload_id": payload.payload_id,
        "tenant_id": payload.tenant_id,
        "source_id": payload.source_id,
        "collector_id": payload.collector_id,
        "event_time_utc": payload.event_time_utc,
        "event_category": payload.event_category,
        "severity": payload.severity.value,
        "health_state": health_value,
        "is_backlog_replay": bool(payload.is_backlog_replay),
    }


def create_app(data_dir: Optional[str] = None, disable_watchdog: bool = False) -> FastAPI:
    runtime = SaasRuntime(data_dir=data_dir, disable_watchdog=disable_watchdog)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await runtime.db.init_db(seed_tenants=_seed_tenants())
        if not runtime.disable_watchdog:
            await runtime.watchdog.start()
        try:
            yield
        finally:
            await runtime.watchdog.stop()
            await runtime.db.close()

    app = FastAPI(title="Multi-Tenant Observability SaaS", version="3.0.0", lifespan=lifespan)
    install_safe_validation_handler(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/healthz")
    async def healthz() -> dict:
        return {
            "status": "ok",
            "service": "saas-control-plane",
            "regions": sorted(REGION_DB_FILES),
        }

    @app.post("/api/v1/auth/login")
    async def login(body: LoginRequest) -> dict:
        try:
            identity = authenticate_demo_user(body.username, body.password)
        except PermissionError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {
            "access_token": issue_tenant_jwt(identity),
            "token_type": "bearer",
            "tenant_id": identity.tenant_id,
            "region": identity.region,
        }

    @app.post("/api/v1/ingest/{region}")
    async def ingest(
        region: str,
        request: IngestBatchRequest,
        x_collector_token: str = Header(default=""),
    ) -> dict:
        _require_region(region)
        identity: CollectorIdentity = verify_collector(x_collector_token, region, request.collector_id)
        for payload in request.batch:
            if payload.tenant_id != identity.tenant_id or payload.region != region:
                raise HTTPException(
                    status_code=403,
                    detail="payload does not match the authenticated collector token",
                )

        cfg = await runtime.cfg_for(identity.tenant_id)
        accepted = 0
        duplicates_blocked = 0
        incidents_touched = 0
        for payload in request.batch:
            outcome = await runtime.engine.process_event(region, payload, cfg)
            if outcome.inserted:
                accepted += 1
                await runtime.broadcast(
                    identity.tenant_id,
                    "telemetry",
                    _telemetry_frame_data(payload, outcome.health_state.value),
                )
            else:
                duplicates_blocked += 1
            for transition in outcome.transitions:
                await runtime.broadcast(identity.tenant_id, "transition", transition)
            if outcome.incident_record is not None:
                incidents_touched += 1
                await runtime.broadcast(
                    identity.tenant_id,
                    "incident",
                    outcome.incident_record.model_dump(mode="json"),
                )
        return {
            "accepted": accepted,
            "duplicates_blocked": duplicates_blocked,
            "incidents_touched": incidents_touched,
        }

    @app.post("/api/v1/heartbeat/{region}")
    async def heartbeat(
        region: str,
        beat: CollectorHeartbeat,
        x_collector_token: str = Header(default=""),
    ) -> dict:
        _require_region(region)
        identity: CollectorIdentity = verify_collector(x_collector_token, region, beat.collector_id)
        if beat.tenant_id != identity.tenant_id or beat.region != region:
            raise HTTPException(
                status_code=403,
                detail="heartbeat does not match the authenticated collector token",
            )

        cfg = await runtime.cfg_for(identity.tenant_id)
        cpu = beat.collector_cpu_pct
        if cpu <= cfg.cpu_good_max:
            health = HealthState.EXCELLENT
        elif cpu <= cfg.cpu_fair_max:
            health = HealthState.GOOD
        else:
            health = HealthState.FAIR

        existing = await runtime.db.get_collector(region, beat.collector_id)
        old_state = existing.get("health_state") if existing else None
        now = utc_now_iso()
        await runtime.db.upsert_collector_heartbeat(
            region, beat, health_state=health.value, heartbeat_time_utc=now
        )

        transitions: List[dict] = []
        if old_state == HealthState.POOR.value and health.value != HealthState.POOR.value:
            transition = await runtime.db.record_transition(
                region,
                tenant_id=identity.tenant_id,
                entity_id=beat.collector_id,
                entity_type="collector",
                old_state=old_state,
                new_state=health.value,
                reason="Collector heartbeat recovered",
                transition_time_utc=now,
            )
            transitions.append(transition)

        await runtime.broadcast(
            identity.tenant_id,
            "collector",
            {
                "collector_id": beat.collector_id,
                "tenant_id": beat.tenant_id,
                "region": region,
                "health_state": health.value,
                "last_heartbeat_utc": now,
                "version": beat.collector_version,
                "cpu_pct": beat.collector_cpu_pct,
                "mem_mb": beat.collector_mem_mb,
                "outbox_pending_count": beat.outbox_pending_count,
                "config_status": beat.config_status,
                "total_sent_count": beat.total_sent_count,
            },
        )
        for transition in transitions:
            await runtime.broadcast(identity.tenant_id, "transition", transition)
        return {
            "accepted": True,
            "collector_id": beat.collector_id,
            "health_state": health.value,
        }

    @app.get("/api/v1/overview")
    async def overview(identity: TenantIdentity = Depends(get_current_tenant)) -> dict:
        region = identity.region
        incident_rows = await runtime.db.list_incidents(region, identity.tenant_id)
        return {
            "tenant_id": identity.tenant_id,
            "region": region,
            "regional_db_file": runtime.db.regional_db_file(region),
            "collectors": await runtime.db.list_collectors(region, identity.tenant_id),
            "sources": await runtime.db.list_sources_state(region, identity.tenant_id),
            "incidents": [
                incident_row_to_record(row, region).model_dump(mode="json")
                for row in incident_rows
            ],
            "recent_transitions": await runtime.db.list_transitions(
                region, identity.tenant_id, limit=60
            ),
        }

    @app.get("/api/v1/sources/{source_id}/series")
    async def source_series(
        source_id: str,
        limit: int = Query(default=120, ge=1, le=500),
        identity: TenantIdentity = Depends(get_current_tenant),
    ) -> dict:
        events = await runtime.db.get_source_series(
            identity.region, identity.tenant_id, source_id, limit
        )
        return {
            "tenant_id": identity.tenant_id,
            "region": identity.region,
            "source_id": source_id,
            "count": len(events),
            "events": events,
        }

    @app.get("/api/v1/incidents")
    async def list_incidents(identity: TenantIdentity = Depends(get_current_tenant)) -> dict:
        region = identity.region
        rows = await runtime.db.list_incidents(region, identity.tenant_id)
        return {
            "tenant_id": identity.tenant_id,
            "region": region,
            "incidents": [
                incident_row_to_record(row, region).model_dump(mode="json") for row in rows
            ],
        }

    @app.post("/api/v1/incidents/{incident_id}/approve")
    async def approve_incident(
        incident_id: str, identity: TenantIdentity = Depends(get_current_tenant)
    ) -> dict:
        return await _transition_remediation(identity, incident_id, approve_remediation)

    @app.post("/api/v1/incidents/{incident_id}/rollback")
    async def rollback_incident(
        incident_id: str, identity: TenantIdentity = Depends(get_current_tenant)
    ) -> dict:
        return await _transition_remediation(identity, incident_id, rollback_remediation)

    async def _transition_remediation(
        identity: TenantIdentity, incident_id: str, transition
    ) -> dict:
        region = identity.region
        row = await runtime.db.get_incident(region, identity.tenant_id, incident_id)
        if row is None:
            raise HTTPException(status_code=404, detail=f"unknown incident: {incident_id}")
        record = incident_row_to_record(row, region)
        try:
            updated = transition(record.remediation, actor=identity.tenant_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        await runtime.db.update_incident_remediation(
            region,
            incident_id=incident_id,
            tenant_id=identity.tenant_id,
            remediation_json=updated.model_dump_json(),
        )
        record = record.model_copy(update={"remediation": updated})
        return record.model_dump(mode="json")

    @app.get("/api/v1/transitions")
    async def transitions(
        limit: int = Query(default=60, ge=1, le=200),
        identity: TenantIdentity = Depends(get_current_tenant),
    ) -> dict:
        rows = await runtime.db.list_transitions(identity.region, identity.tenant_id, limit=limit)
        return {
            "tenant_id": identity.tenant_id,
            "region": identity.region,
            "transitions": rows,
        }

    @app.get("/api/v1/thresholds")
    async def get_thresholds(identity: TenantIdentity = Depends(get_current_tenant)) -> dict:
        row = await runtime.db.get_threshold_config(identity.tenant_id)
        config = ThresholdConfig()
        updated_utc = None
        if row and row.get("config_json"):
            try:
                config = ThresholdConfig.model_validate_json(row["config_json"])
                updated_utc = row.get("updated_utc")
            except ValidationError:
                pass
        return {
            "tenant_id": identity.tenant_id,
            "config": config.model_dump(),
            "updated_utc": updated_utc,
        }

    @app.put("/api/v1/thresholds")
    async def put_thresholds(
        config: ThresholdConfig, identity: TenantIdentity = Depends(get_current_tenant)
    ) -> dict:
        await runtime.db.set_threshold_config(identity.tenant_id, config)
        return {
            "tenant_id": identity.tenant_id,
            "config": config.model_dump(),
            "updated_utc": utc_now_iso(),
        }

    @app.get("/api/v1/sla-metrics")
    async def sla_metrics(identity: TenantIdentity = Depends(get_current_tenant)) -> dict:
        region = identity.region
        ingest_latencies = await runtime.db.sla_ingest_latency_secs(region, identity.tenant_id)
        alert_latencies = await runtime.db.sla_alert_latency_secs(region, identity.tenant_id)
        offline_detections = await runtime.db.sla_offline_detection_secs(
            region, identity.tenant_id
        )
        totals = await runtime.db.sla_totals(region, identity.tenant_id)
        return {
            "tenant_id": identity.tenant_id,
            "region": region,
            "ingest_latency_p95_sec": _p95(ingest_latencies),
            "alert_latency_latest_sec": alert_latencies[-1] if alert_latencies else None,
            "alert_latency_p95_sec": _p95(alert_latencies),
            "collector_offline_detection_sec": (
                max(offline_detections) if offline_detections else None
            ),
            "total_sent_count": totals["total_sent_count"],
            "total_received_count": totals["total_received_count"],
            "lost_count": max(
                0, totals["total_sent_count"] - totals["total_received_count"]
            ),
            "duplicates_blocked_count": totals["duplicates_blocked_count"],
            "backlog_replayed_count": totals["backlog_replayed_count"],
        }

    @app.websocket("/ws/{tenant_id}")
    async def tenant_websocket(
        websocket: WebSocket, tenant_id: str, token: str = Query(default="")
    ) -> None:
        if not verify_ws_token(token, tenant_id):
            await websocket.close(code=1008)
            return
        await runtime.ws.connect(tenant_id, websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await runtime.ws.disconnect(tenant_id, websocket)

    return app


app = create_app()
