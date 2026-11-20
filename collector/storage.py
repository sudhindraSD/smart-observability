"""Slice 2 Box 1 persistence: the raw telemetry vault, egress outbox and
egress audit log, all in one local SQLite file inside the customer network.

``raw_telemetry`` never leaves Box 1 and is pruned on a rolling retention
window; ``egress_outbox`` is the durable queue that survives a hard SaaS
outage; ``egress_audit_log`` records the exact bytes (plus SHA-256) of every
payload that crossed the wire, keyed by ``payload_id`` with
``INSERT OR REPLACE`` so retries overwrite cleanly.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import aiosqlite

from shared.contracts import EgressMetadataPayload, InternalRawEvent, utc_now_iso

STATUS_PENDING = "PENDING"
STATUS_SENT = "SENT"

_RAW_TABLE = """
CREATE TABLE IF NOT EXISTS raw_telemetry (
    raw_id             TEXT PRIMARY KEY,
    event_time_utc     TEXT,
    collected_time_utc TEXT,
    raw_json           TEXT,
    redacted_preview   TEXT,
    expires_at_utc     TEXT
)
"""

_OUTBOX_TABLE = """
CREATE TABLE IF NOT EXISTS egress_outbox (
    payload_id   TEXT PRIMARY KEY,
    raw_id       TEXT,
    payload_json TEXT,
    status       TEXT,
    retry_count  INTEGER,
    created_utc  TEXT,
    sent_utc     TEXT
)
"""

_AUDIT_TABLE = """
CREATE TABLE IF NOT EXISTS egress_audit_log (
    payload_id              TEXT PRIMARY KEY,
    raw_id                  TEXT,
    payload_sha256          TEXT,
    payload_json            TEXT,
    redaction_summary_json  TEXT,
    logged_utc              TEXT
)
"""


class CollectorStorage:
    """Async SQLite facade over the three Slice 2 tables."""

    def __init__(self, db_path: str = "data/collector_bank_a.db") -> None:
        self._db_path = db_path
        self._db: Optional[aiosqlite.Connection] = None

    # -- lifecycle -----------------------------------------------------------

    async def init_db(self) -> None:
        parent = os.path.dirname(os.path.abspath(self._db_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA journal_mode=WAL;")
        await self._db.execute("PRAGMA synchronous=NORMAL;")
        await self._db.execute("PRAGMA busy_timeout=5000;")
        await self._db.execute(_RAW_TABLE)
        await self._db.execute(_OUTBOX_TABLE)
        await self._db.execute(_AUDIT_TABLE)
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    @property
    def db_path(self) -> str:
        return self._db_path

    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("init_db() must be called before use")
        return self._db

    # -- writes ---------------------------------------------------------------

    async def save_raw_and_queue(
        self,
        raw: InternalRawEvent,
        payload: EgressMetadataPayload,
        redacted_preview: str = "",
        expires_at_utc: Optional[str] = None,
    ) -> str:
        """Persist the raw event locally and enqueue its egress payload as
        PENDING in one transaction. Returns the ``payload_id``."""
        conn = self._conn()
        try:
            await conn.execute(
                "INSERT OR REPLACE INTO raw_telemetry "
                "(raw_id, event_time_utc, collected_time_utc, raw_json, "
                " redacted_preview, expires_at_utc) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    raw.raw_id,
                    raw.event_time_utc,
                    payload.collected_time_utc,
                    raw.model_dump_json(),
                    redacted_preview,
                    expires_at_utc,
                ),
            )
            await conn.execute(
                "INSERT OR REPLACE INTO egress_outbox "
                "(payload_id, raw_id, payload_json, status, retry_count, "
                " created_utc, sent_utc) VALUES (?, ?, ?, ?, ?, ?, NULL)",
                (
                    payload.payload_id,
                    raw.raw_id,
                    payload.model_dump_json(),
                    STATUS_PENDING,
                    0,
                    utc_now_iso(),
                ),
            )
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise
        return payload.payload_id

    async def record_audit_snapshot(
        self,
        payload_id: str,
        raw_id: str,
        payload_sha256: str,
        payload_json: str,
        redaction_summary_json: str,
        logged_utc: str,
    ) -> None:
        """INSERT OR REPLACE so a retried payload overwrites its old audit."""
        conn = self._conn()
        await conn.execute(
            "INSERT OR REPLACE INTO egress_audit_log "
            "(payload_id, raw_id, payload_sha256, payload_json, "
            " redaction_summary_json, logged_utc) VALUES (?, ?, ?, ?, ?, ?)",
            (
                payload_id,
                raw_id,
                payload_sha256,
                payload_json,
                redaction_summary_json,
                logged_utc,
            ),
        )
        await conn.commit()

    # -- outbox drain ----------------------------------------------------------

    async def fetch_pending_batch(self, limit: int = 25) -> List[Dict[str, Any]]:
        conn = self._conn()
        cursor = await conn.execute(
            "SELECT payload_id, raw_id, payload_json, retry_count, created_utc "
            "FROM egress_outbox WHERE status = ? "
            "ORDER BY created_utc ASC, rowid ASC LIMIT ?",
            (STATUS_PENDING, limit),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def mark_sent(self, payload_ids: List[str], sent_utc: str) -> None:
        if not payload_ids:
            return
        conn = self._conn()
        placeholders = ",".join("?" for _ in payload_ids)
        await conn.execute(
            f"UPDATE egress_outbox SET status = ?, sent_utc = ? "
            f"WHERE payload_id IN ({placeholders})",
            (STATUS_SENT, sent_utc, *payload_ids),
        )
        await conn.commit()

    async def increment_retry(self, payload_ids: List[str]) -> None:
        if not payload_ids:
            return
        conn = self._conn()
        placeholders = ",".join("?" for _ in payload_ids)
        await conn.execute(
            f"UPDATE egress_outbox SET retry_count = retry_count + 1 "
            f"WHERE payload_id IN ({placeholders})",
            tuple(payload_ids),
        )
        await conn.commit()

    # -- reads ------------------------------------------------------------------

    async def get_egress_proof_rows(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Side-by-side proof rows: raw local record joined with the exact
        egress payload and its audit snapshot."""
        conn = self._conn()
        cursor = await conn.execute(
            "SELECT o.payload_id, o.raw_id, o.status, o.retry_count, "
            "       o.created_utc, o.sent_utc, o.payload_json, "
            "       r.event_time_utc, r.collected_time_utc, r.raw_json, "
            "       r.redacted_preview, r.expires_at_utc, "
            "       a.payload_sha256, a.payload_json AS audit_payload_json, "
            "       a.redaction_summary_json, a.logged_utc "
            "FROM egress_outbox o "
            "LEFT JOIN raw_telemetry r ON r.raw_id = o.raw_id "
            "LEFT JOIN egress_audit_log a ON a.payload_id = o.payload_id "
            "ORDER BY o.created_utc DESC, o.rowid DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [dict(row) for row in rows]

    async def get_counts(self) -> Dict[str, int]:
        conn = self._conn()
        cursor = await conn.execute(
            "SELECT "
            " (SELECT COUNT(*) FROM egress_outbox WHERE status = ?) AS pending_count, "
            " (SELECT COUNT(*) FROM egress_outbox WHERE status = ?) AS total_sent_count, "
            " (SELECT COUNT(*) FROM raw_telemetry) AS raw_count",
            (STATUS_PENDING, STATUS_SENT),
        )
        row = await cursor.fetchone()
        await cursor.close()
        assert row is not None
        return {
            "pending_count": row["pending_count"],
            "total_sent_count": row["total_sent_count"],
            "raw_count": row["raw_count"],
        }

    async def get_sent_payload_ids(self) -> List[str]:
        conn = self._conn()
        cursor = await conn.execute(
            "SELECT payload_id FROM egress_outbox WHERE status = ? "
            "ORDER BY sent_utc ASC, rowid ASC",
            (STATUS_SENT,),
        )
        rows = await cursor.fetchall()
        await cursor.close()
        return [row["payload_id"] for row in rows]

    # -- retention ----------------------------------------------------------------

    async def prune_expired_raw(self, now_utc: str) -> int:
        """Delete raw telemetry rows past their retention window. The outbox
        and audit log keep their copies of the (already scrubbed) payload."""
        conn = self._conn()
        cursor = await conn.execute(
            "DELETE FROM raw_telemetry "
            "WHERE expires_at_utc IS NOT NULL AND expires_at_utc <= ?",
            (now_utc,),
        )
        deleted = cursor.rowcount or 0
        await cursor.close()
        await conn.commit()
        return deleted
