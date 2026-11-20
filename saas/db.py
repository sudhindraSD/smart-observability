"""Slice 3 storage: one control-plane DB plus one SQLite WAL DB per region.

Physical regional data residency is proven by physically separate database
files under ``SAAS_DATA_DIR`` (default ``data/``):

* ``saas_control_plane.db`` — tenants + per-tenant threshold configuration.
* ``saas_ap_south_1.db``   — ALL regional data for ap-south-1.
* ``saas_eu_west_1.db``    — ALL regional data for eu-west-1.

Pure ``aiosqlite``; no ORM, no migrations framework. Ingest idempotency is
``INSERT OR IGNORE`` on ``payload_id``; all time-series reads order by
``event_time_utc ASC`` (event-time ordering, never ingest order).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import aiosqlite

from shared.contracts import (
    CollectorHeartbeat,
    EgressMetadataPayload,
    IncidentRecord,
    ThresholdConfig,
    utc_now_iso,
)

REGION_DB_FILES: Dict[str, str] = {
    "ap-south-1": "saas_ap_south_1.db",
    "eu-west-1": "saas_eu_west_1.db",
}
CONTROL_PLANE_DB_FILE = "saas_control_plane.db"

_PRAGMAS = (
    "PRAGMA journal_mode=WAL;",
    "PRAGMA synchronous=NORMAL;",
    "PRAGMA busy_timeout=5000;",
)

_REGION_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS telemetry_events (
        payload_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        collector_id TEXT,
        source_id TEXT,
        source_type TEXT,
        upstream_source_id TEXT,
        event_time_utc TEXT,
        source_timezone TEXT,
        collected_time_utc TEXT,
        egress_sent_utc TEXT,
        ingested_time_utc TEXT,
        is_backlog_replay INTEGER,
        metrics_json TEXT,
        security_json TEXT,
        event_category TEXT,
        severity TEXT,
        health_state TEXT,
        alert_context TEXT,
        redaction_audit_json TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_te_tenant_src_time ON telemetry_events(tenant_id, source_id, event_time_utc)",
    """
    CREATE TABLE IF NOT EXISTS collectors (
        collector_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        region TEXT,
        health_state TEXT,
        last_heartbeat_utc TEXT,
        offline_detected_utc TEXT,
        version TEXT,
        cpu_pct REAL,
        mem_mb REAL,
        outbox_pending_count INTEGER,
        config_status TEXT,
        total_sent_count INTEGER,
        total_received_count INTEGER,
        duplicates_blocked_count INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS sources_state (
        tenant_id TEXT,
        source_id TEXT,
        collector_id TEXT,
        source_type TEXT,
        upstream_source_id TEXT,
        health_state TEXT,
        latest_event_time_utc TEXT,
        last_ingested_utc TEXT,
        latest_metrics_json TEXT,
        latest_security_json TEXT,
        secrets_scrubbed_total INTEGER DEFAULT 0,
        PRIMARY KEY (tenant_id, source_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS health_transitions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT,
        entity_id TEXT,
        entity_type TEXT,
        old_state TEXT,
        new_state TEXT,
        reason TEXT,
        transition_time_utc TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        tenant_id TEXT,
        collector_id TEXT,
        status TEXT,
        severity TEXT,
        root_cause_source_id TEXT,
        affected_sources_json TEXT,
        merged_alert_count INTEGER,
        first_event_time_utc TEXT,
        alert_created_utc TEXT,
        explanation_json TEXT,
        remediation_json TEXT
    )
    """,
]

_CONTROL_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS tenants (
        tenant_id TEXT PRIMARY KEY,
        region TEXT,
        display_name TEXT,
        created_utc TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS threshold_config (
        tenant_id TEXT PRIMARY KEY,
        config_json TEXT,
        updated_utc TEXT
    )
    """,
]


def _dump(value) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


class SaasDatabase:
    """Owns one aiosqlite connection per database file."""

    def __init__(self, data_dir: Optional[str] = None) -> None:
        env_dir = os.environ.get("SAAS_DATA_DIR", "").strip()
        self.data_dir = Path(data_dir or env_dir or "data")
        self._conns: Dict[str, aiosqlite.Connection] = {}

    # -- paths -----------------------------------------------------------------

    def control_plane_path(self) -> Path:
        return self.data_dir / CONTROL_PLANE_DB_FILE

    def region_db_path(self, region: str) -> Path:
        filename = REGION_DB_FILES.get(region)
        if filename is None:
            raise KeyError(f"unknown region: {region}")
        return self.data_dir / filename

    def regional_db_file(self, region: str) -> str:
        return REGION_DB_FILES[region]

    # -- lifecycle ---------------------------------------------------------------

    async def _connect(self, path: Path) -> aiosqlite.Connection:
        conn = await aiosqlite.connect(str(path))
        conn.row_factory = aiosqlite.Row
        for pragma in _PRAGMAS:
            await conn.execute(pragma)
        return conn

    async def init_db(self, seed_tenants: Sequence[dict]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        control = await self._connect(self.control_plane_path())
        self._conns["control"] = control
        for statement in _CONTROL_SCHEMA:
            await control.execute(statement)
        for tenant in seed_tenants:
            await control.execute(
                "INSERT OR IGNORE INTO tenants (tenant_id, region, display_name, created_utc)"
                " VALUES (?, ?, ?, ?)",
                (
                    tenant["tenant_id"],
                    tenant["region"],
                    tenant.get("display_name", tenant["tenant_id"]),
                    utc_now_iso(),
                ),
            )
        await control.commit()
        for region in REGION_DB_FILES:
            conn = await self._connect(self.region_db_path(region))
            self._conns[region] = conn
            for statement in _REGION_SCHEMA:
                await conn.execute(statement)
            await conn.commit()

    async def close(self) -> None:
        for conn in self._conns.values():
            await conn.close()
        self._conns.clear()

    def _conn(self, region: str) -> aiosqlite.Connection:
        return self._conns[region]

    # -- telemetry (idempotent, event-time ordered) ---------------------------------

    async def insert_telemetry_event(
        self,
        region: str,
        payload: EgressMetadataPayload,
        *,
        ingested_time_utc: str,
        health_state: str,
    ) -> bool:
        """INSERT OR IGNORE on payload_id. Returns True when the row was new."""
        cursor = await self._conn(region).execute(
            """
            INSERT OR IGNORE INTO telemetry_events (
                payload_id, tenant_id, collector_id, source_id, source_type,
                upstream_source_id, event_time_utc, source_timezone,
                collected_time_utc, egress_sent_utc, ingested_time_utc,
                is_backlog_replay, metrics_json, security_json,
                event_category, severity, health_state, alert_context,
                redaction_audit_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.payload_id,
                payload.tenant_id,
                payload.collector_id,
                payload.source_id,
                payload.source_type.value,
                payload.upstream_source_id,
                payload.event_time_utc,
                payload.source_timezone,
                payload.collected_time_utc,
                payload.egress_sent_utc,
                ingested_time_utc,
                1 if payload.is_backlog_replay else 0,
                payload.metrics.model_dump_json(),
                payload.security_summary.model_dump_json(),
                payload.event_category,
                payload.severity.value,
                health_state,
                payload.alert_context,
                payload.redaction_audit.model_dump_json(),
            ),
        )
        inserted = cursor.rowcount == 1
        await self._conn(region).commit()
        return inserted

    async def get_telemetry_row(
        self, region: str, tenant_id: str, payload_id: str
    ) -> Optional[dict]:
        cursor = await self._conn(region).execute(
            "SELECT * FROM telemetry_events WHERE tenant_id = ? AND payload_id = ?",
            (tenant_id, payload_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def count_telemetry_rows(
        self, region: str, tenant_id: str, source_id: Optional[str] = None
    ) -> int:
        sql = "SELECT COUNT(*) FROM telemetry_events WHERE tenant_id = ?"
        params: list = [tenant_id]
        if source_id is not None:
            sql += " AND source_id = ?"
            params.append(source_id)
        cursor = await self._conn(region).execute(sql, params)
        row = await cursor.fetchone()
        return int(row[0])

    # -- collectors ----------------------------------------------------------------

    async def upsert_collector_heartbeat(
        self,
        region: str,
        beat: CollectorHeartbeat,
        *,
        health_state: str,
        heartbeat_time_utc: str,
    ) -> None:
        await self._conn(region).execute(
            """
            INSERT INTO collectors (
                collector_id, tenant_id, region, health_state,
                last_heartbeat_utc, offline_detected_utc, version, cpu_pct,
                mem_mb, outbox_pending_count, config_status,
                total_sent_count, total_received_count, duplicates_blocked_count
            ) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 0, 0)
            ON CONFLICT(collector_id) DO UPDATE SET
                health_state = excluded.health_state,
                last_heartbeat_utc = excluded.last_heartbeat_utc,
                offline_detected_utc = NULL,
                version = excluded.version,
                cpu_pct = excluded.cpu_pct,
                mem_mb = excluded.mem_mb,
                outbox_pending_count = excluded.outbox_pending_count,
                config_status = excluded.config_status,
                total_sent_count = excluded.total_sent_count
            """,
            (
                beat.collector_id,
                beat.tenant_id,
                beat.region,
                health_state,
                heartbeat_time_utc,
                beat.collector_version,
                beat.collector_cpu_pct,
                beat.collector_mem_mb,
                beat.outbox_pending_count,
                beat.config_status,
                beat.total_sent_count,
            ),
        )
        await self._conn(region).commit()

    async def get_collector(
        self, region: str, collector_id: str
    ) -> Optional[dict]:
        cursor = await self._conn(region).execute(
            "SELECT * FROM collectors WHERE collector_id = ?",
            (collector_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_collectors(self, region: str, tenant_id: Optional[str] = None) -> List[dict]:
        sql = "SELECT * FROM collectors"
        params: list = []
        if tenant_id is not None:
            sql += " WHERE tenant_id = ?"
            params.append(tenant_id)
        sql += " ORDER BY collector_id"
        cursor = await self._conn(region).execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def bump_collector_counter(
        self, region: str, tenant_id: str, collector_id: str, field: str
    ) -> None:
        assert field in ("total_received_count", "duplicates_blocked_count")
        await self._conn(region).execute(
            f"""
            INSERT INTO collectors (
                collector_id, tenant_id, region, health_state,
                total_sent_count, total_received_count, duplicates_blocked_count
            ) VALUES (?, ?, ?, 'Unknown', 0,
                {1 if field == 'total_received_count' else 0},
                {1 if field == 'duplicates_blocked_count' else 0})
            ON CONFLICT(collector_id) DO UPDATE SET {field} = {field} + 1
            """,
            (collector_id, tenant_id, region),
        )
        await self._conn(region).commit()

    async def set_collector_offline(
        self, region: str, collector_id: str, offline_time_utc: str
    ) -> None:
        await self._conn(region).execute(
            "UPDATE collectors SET health_state = 'Poor', offline_detected_utc = ?"
            " WHERE collector_id = ?",
            (offline_time_utc, collector_id),
        )
        await self._conn(region).commit()

    async def set_collector_health(
        self, region: str, collector_id: str, health_state: str
    ) -> None:
        await self._conn(region).execute(
            "UPDATE collectors SET health_state = ? WHERE collector_id = ?",
            (health_state, collector_id),
        )
        await self._conn(region).commit()

    # -- sources state ------------------------------------------------------------

    async def get_source_state(
        self, region: str, tenant_id: str, source_id: str
    ) -> Optional[dict]:
        cursor = await self._conn(region).execute(
            "SELECT * FROM sources_state WHERE tenant_id = ? AND source_id = ?",
            (tenant_id, source_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_sources_state(
        self, region: str, tenant_id: Optional[str] = None
    ) -> List[dict]:
        sql = "SELECT * FROM sources_state"
        params: list = []
        if tenant_id is not None:
            sql += " WHERE tenant_id = ?"
            params.append(tenant_id)
        sql += " ORDER BY source_id"
        cursor = await self._conn(region).execute(sql, params)
        return [dict(row) for row in await cursor.fetchall()]

    async def upsert_source_state(
        self,
        region: str,
        *,
        tenant_id: str,
        source_id: str,
        collector_id: str,
        source_type: str,
        upstream_source_id: Optional[str],
        health_state: str,
        latest_event_time_utc: str,
        last_ingested_utc: str,
        latest_metrics_json: str,
        latest_security_json: str,
        secrets_scrubbed_delta: int,
    ) -> None:
        await self._conn(region).execute(
            """
            INSERT INTO sources_state (
                tenant_id, source_id, collector_id, source_type,
                upstream_source_id, health_state, latest_event_time_utc,
                last_ingested_utc, latest_metrics_json, latest_security_json,
                secrets_scrubbed_total
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, source_id) DO UPDATE SET
                collector_id = excluded.collector_id,
                source_type = excluded.source_type,
                upstream_source_id = excluded.upstream_source_id,
                health_state = excluded.health_state,
                latest_event_time_utc = excluded.latest_event_time_utc,
                last_ingested_utc = excluded.last_ingested_utc,
                latest_metrics_json = excluded.latest_metrics_json,
                latest_security_json = excluded.latest_security_json,
                secrets_scrubbed_total = secrets_scrubbed_total
                    + excluded.secrets_scrubbed_total
            """,
            (
                tenant_id,
                source_id,
                collector_id,
                source_type,
                upstream_source_id,
                health_state,
                latest_event_time_utc,
                last_ingested_utc,
                latest_metrics_json,
                latest_security_json,
                secrets_scrubbed_delta,
            ),
        )
        await self._conn(region).commit()

    async def set_source_health(
        self, region: str, tenant_id: str, source_id: str, health_state: str
    ) -> None:
        await self._conn(region).execute(
            "UPDATE sources_state SET health_state = ?"
            " WHERE tenant_id = ? AND source_id = ?",
            (health_state, tenant_id, source_id),
        )
        await self._conn(region).commit()

    # -- time series (event-time ordering is mandatory) ------------------------------

    async def get_source_series(
        self, region: str, tenant_id: str, source_id: str, limit: int
    ) -> List[dict]:
        rows = await self._conn(region).execute(
            """
            SELECT * FROM (
                SELECT * FROM telemetry_events
                WHERE tenant_id = ? AND source_id = ?
                ORDER BY event_time_utc DESC LIMIT ?
            ) ORDER BY event_time_utc ASC
            """,
            (tenant_id, source_id, limit),
        )
        return [dict(row) for row in await rows.fetchall()]

    # -- health transitions ----------------------------------------------------------

    async def record_transition(
        self,
        region: str,
        *,
        tenant_id: str,
        entity_id: str,
        entity_type: str,
        old_state: Optional[str],
        new_state: str,
        reason: str,
        transition_time_utc: str,
    ) -> dict:
        await self._conn(region).execute(
            """
            INSERT INTO health_transitions (
                tenant_id, entity_id, entity_type, old_state, new_state,
                reason, transition_time_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                entity_id,
                entity_type,
                old_state,
                new_state,
                reason,
                transition_time_utc,
            ),
        )
        await self._conn(region).commit()
        return {
            "tenant_id": tenant_id,
            "entity_id": entity_id,
            "entity_type": entity_type,
            "old_state": old_state,
            "new_state": new_state,
            "reason": reason,
            "transition_time_utc": transition_time_utc,
        }

    async def list_transitions(
        self, region: str, tenant_id: str, limit: int = 60
    ) -> List[dict]:
        cursor = await self._conn(region).execute(
            """
            SELECT * FROM health_transitions WHERE tenant_id = ?
            ORDER BY id DESC LIMIT ?
            """,
            (tenant_id, limit),
        )
        return [dict(row) for row in await cursor.fetchall()]

    # -- incidents -------------------------------------------------------------------

    async def insert_incident(self, region: str, record: IncidentRecord) -> None:
        await self._conn(region).execute(
            """
            INSERT INTO incidents (
                incident_id, tenant_id, collector_id, status, severity,
                root_cause_source_id, affected_sources_json,
                merged_alert_count, first_event_time_utc, alert_created_utc,
                explanation_json, remediation_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.incident_id,
                record.tenant_id,
                record.collector_id,
                record.status,
                record.severity.value,
                record.root_cause_source_id,
                _dump(record.affected_source_ids),
                record.merged_alert_count,
                record.first_event_time_utc,
                record.alert_created_utc,
                record.explanation.model_dump_json(),
                record.remediation.model_dump_json(),
            ),
        )
        await self._conn(region).commit()

    async def update_incident_merge(
        self,
        region: str,
        *,
        incident_id: str,
        tenant_id: str,
        severity: str,
        root_cause_source_id: str,
        affected_source_ids: List[str],
        merged_alert_count: int,
        first_event_time_utc: str,
        explanation_json: str,
    ) -> None:
        await self._conn(region).execute(
            """
            UPDATE incidents SET severity = ?, root_cause_source_id = ?,
                affected_sources_json = ?, merged_alert_count = ?,
                first_event_time_utc = ?, explanation_json = ?
            WHERE incident_id = ? AND tenant_id = ?
            """,
            (
                severity,
                root_cause_source_id,
                _dump(affected_source_ids),
                merged_alert_count,
                first_event_time_utc,
                explanation_json,
                incident_id,
                tenant_id,
            ),
        )
        await self._conn(region).commit()

    async def update_incident_remediation(
        self,
        region: str,
        *,
        incident_id: str,
        tenant_id: str,
        remediation_json: str,
    ) -> None:
        await self._conn(region).execute(
            "UPDATE incidents SET remediation_json = ?"
            " WHERE incident_id = ? AND tenant_id = ?",
            (remediation_json, incident_id, tenant_id),
        )
        await self._conn(region).commit()

    async def get_incident(
        self, region: str, tenant_id: str, incident_id: str
    ) -> Optional[dict]:
        cursor = await self._conn(region).execute(
            "SELECT * FROM incidents WHERE incident_id = ? AND tenant_id = ?",
            (incident_id, tenant_id),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_incidents(
        self, region: str, tenant_id: str, *, open_only: bool = False
    ) -> List[dict]:
        sql = "SELECT * FROM incidents WHERE tenant_id = ?"
        if open_only:
            sql += " AND status = 'OPEN'"
        sql += " ORDER BY alert_created_utc DESC"
        cursor = await self._conn(region).execute(sql, (tenant_id,))
        return [dict(row) for row in await cursor.fetchall()]

    # -- control plane ----------------------------------------------------------------

    async def get_threshold_config(self, tenant_id: str) -> Optional[dict]:
        cursor = await self._conns["control"].execute(
            "SELECT tenant_id, config_json, updated_utc FROM threshold_config"
            " WHERE tenant_id = ?",
            (tenant_id,),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def set_threshold_config(
        self, tenant_id: str, config: ThresholdConfig
    ) -> None:
        await self._conns["control"].execute(
            """
            INSERT INTO threshold_config (tenant_id, config_json, updated_utc)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
                config_json = excluded.config_json,
                updated_utc = excluded.updated_utc
            """,
            (tenant_id, config.model_dump_json(), utc_now_iso()),
        )
        await self._conns["control"].commit()

    # -- SLA metrics -------------------------------------------------------------------

    async def sla_ingest_latency_secs(
        self, region: str, tenant_id: str, max_rows: int = 2000
    ) -> List[float]:
        from shared.contracts import parse_utc_iso

        cursor = await self._conn(region).execute(
            """
            SELECT event_time_utc, ingested_time_utc FROM telemetry_events
            WHERE tenant_id = ? AND COALESCE(is_backlog_replay, 0) = 0
                AND ingested_time_utc IS NOT NULL
            ORDER BY ingested_time_utc DESC LIMIT ?
            """,
            (tenant_id, max_rows),
        )
        latencies: List[float] = []
        for row in await cursor.fetchall():
            try:
                delta = (
                    parse_utc_iso(row["ingested_time_utc"])
                    - parse_utc_iso(row["event_time_utc"])
                ).total_seconds()
            except (ValueError, TypeError):
                continue
            if delta >= 0:
                latencies.append(delta)
        return latencies

    async def sla_alert_latency_secs(self, region: str, tenant_id: str) -> List[float]:
        from shared.contracts import parse_utc_iso

        cursor = await self._conn(region).execute(
            "SELECT first_event_time_utc, alert_created_utc FROM incidents"
            " WHERE tenant_id = ? ORDER BY alert_created_utc ASC",
            (tenant_id,),
        )
        latencies: List[float] = []
        for row in await cursor.fetchall():
            try:
                delta = (
                    parse_utc_iso(row["alert_created_utc"])
                    - parse_utc_iso(row["first_event_time_utc"])
                ).total_seconds()
            except (ValueError, TypeError):
                continue
            if delta >= 0:
                latencies.append(delta)
        return latencies

    async def sla_offline_detection_secs(self, region: str, tenant_id: str) -> List[float]:
        from shared.contracts import parse_utc_iso

        cursor = await self._conn(region).execute(
            "SELECT last_heartbeat_utc, offline_detected_utc FROM collectors"
            " WHERE tenant_id = ? AND offline_detected_utc IS NOT NULL"
            " AND last_heartbeat_utc IS NOT NULL",
            (tenant_id,),
        )
        values: List[float] = []
        for row in await cursor.fetchall():
            try:
                delta = (
                    parse_utc_iso(row["offline_detected_utc"])
                    - parse_utc_iso(row["last_heartbeat_utc"])
                ).total_seconds()
            except (ValueError, TypeError):
                continue
            if delta >= 0:
                values.append(delta)
        return values

    async def sla_totals(self, region: str, tenant_id: str) -> dict:
        cursor = await self._conn(region).execute(
            """
            SELECT COALESCE(SUM(total_sent_count), 0) AS sent,
                   COALESCE(SUM(total_received_count), 0) AS received,
                   COALESCE(SUM(duplicates_blocked_count), 0) AS dupes
            FROM collectors WHERE tenant_id = ?
            """,
            (tenant_id,),
        )
        row = await cursor.fetchone()
        backlog_cursor = await self._conn(region).execute(
            "SELECT COUNT(*) FROM telemetry_events"
            " WHERE tenant_id = ? AND COALESCE(is_backlog_replay, 0) = 1",
            (tenant_id,),
        )
        backlog_row = await backlog_cursor.fetchone()
        return {
            "total_sent_count": int(row["sent"]),
            "total_received_count": int(row["received"]),
            "duplicates_blocked_count": int(row["dupes"]),
            "backlog_replayed_count": int(backlog_row[0]),
        }
