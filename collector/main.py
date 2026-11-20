"""Box 1 collector FastAPI app: local ingestion, egress proof panel, control.

Configuration comes from environment variables with clean defaults for
Collector A (bank-a / ap-south-1 / col-blr-01). ``create_app()`` reads the
environment at call time so tests can build isolated instances; the module
level ``app`` is the production entry point.
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from collector.adapter import StreamAdapter
from collector.scrubber import LocalScrubber
from collector.sender import EgressSender
from collector.storage import CollectorStorage
from shared.contracts import (
    InternalRawEvent,
    parse_utc_iso,
    utc_now_iso,
)
from shared.safe_errors import install_safe_validation_handler

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_PRUNE_INTERVAL_SEC = 60.0


def _env(key: str, default: str) -> str:
    value = os.getenv(key)
    return value if value is not None and value != "" else default


def _env_bool(key: str, default: bool = False) -> bool:
    return _env(key, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _expires_at_iso(collected_iso: str, retention_minutes: int) -> str:
    expires = parse_utc_iso(collected_iso) + timedelta(minutes=retention_minutes)
    return expires.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CollectorRuntime:
    """Everything the endpoints and background loops share."""

    def __init__(self) -> None:
        self.tenant_id = _env("TENANT_ID", "bank-a")
        self.region = _env("REGION", "ap-south-1")
        self.collector_id = _env("COLLECTOR_ID", "col-blr-01")
        self.collector_token = _env("COLLECTOR_TOKEN", "tok-bank-a-blr")
        self.collector_port = int(_env("COLLECTOR_PORT", "4001"))
        self.stream_mode = _env("STREAM_MODE", "live").strip().lower()
        self.retention_minutes = int(_env("LOCAL_RETENTION_MINUTES", "60"))
        self.disable_bg_tasks = _env_bool("COLLECTOR_DISABLE_BG_TASKS", False)

        self.storage = CollectorStorage(
            db_path=_env("COLLECTOR_DB_PATH", "data/collector_bank_a.db")
        )
        self.scrubber = LocalScrubber(
            local_hmac_salt=_env("LOCAL_HMAC_SALT", "bank-a-local-only-salt")
        )
        self.sender = EgressSender(
            self.storage,
            tenant_id=self.tenant_id,
            region=self.region,
            collector_id=self.collector_id,
            saas_base_url=_env("SAAS_BASE_URL", "https://localhost:8000"),
            collector_token=self.collector_token,
            saas_tls_verify=_env_bool("SAAS_TLS_VERIFY", False),
            saas_ca_cert=os.getenv("SAAS_CA_CERT") or None,
        )
        self.adapter = StreamAdapter.from_env()
        self.tasks: List[asyncio.Task] = []

    async def handle_raw(self, raw: InternalRawEvent) -> str:
        """Scrub one raw event and persist raw + queued egress atomically."""
        collected = utc_now_iso()
        payload, scan = self.scrubber.scrub_to_egress(
            raw,
            tenant_id=self.tenant_id,
            region=self.region,
            collector_id=self.collector_id,
            collected_time_utc=collected,
        )
        return await self.storage.save_raw_and_queue(
            raw,
            payload,
            redacted_preview=scan.redacted_preview,
            expires_at_utc=_expires_at_iso(collected, self.retention_minutes),
        )

    async def _adapter_consumer(self) -> None:
        async for event in self.adapter.events():
            try:
                await self.handle_raw(event)
            except asyncio.CancelledError:
                raise
            except Exception:
                import logging

                logging.getLogger(__name__).exception(
                    "failed to persist adapted event"
                )

    async def _prune_loop(self) -> None:
        while True:
            await asyncio.sleep(_PRUNE_INTERVAL_SEC)
            try:
                await self.storage.prune_expired_raw(utc_now_iso())
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

    def start_background_tasks(self) -> None:
        if self.disable_bg_tasks:
            return
        self.tasks.append(
            asyncio.create_task(self._adapter_consumer(), name="adapter-consumer")
        )
        self.tasks.append(
            asyncio.create_task(self.sender.sender_loop(), name="egress-sender")
        )
        self.tasks.append(
            asyncio.create_task(self.sender.heartbeat_loop(), name="heartbeat")
        )
        self.tasks.append(
            asyncio.create_task(self._prune_loop(), name="raw-pruner")
        )

    async def shutdown(self) -> None:
        for task in self.tasks:
            task.cancel()
        for task in self.tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self.tasks.clear()
        await self.sender.aclose()
        await self.storage.close()


def create_app() -> FastAPI:
    runtime = CollectorRuntime()

    @asynccontextmanager
    async def _lifespan(application: FastAPI):
        await runtime.storage.init_db()
        runtime.start_background_tasks()
        yield
        await runtime.shutdown()

    app = FastAPI(title="Box 1 Collector", version="2.0.0", lifespan=_lifespan)
    install_safe_validation_handler(app)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.state.runtime = runtime

    # -- endpoints ---------------------------------------------------------------

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")

    @app.get("/api/status")
    async def status() -> Dict[str, object]:
        counts = await runtime.storage.get_counts()
        return {
            "collector_id": runtime.collector_id,
            "tenant_id": runtime.tenant_id,
            "region": runtime.region,
            "stream_mode": runtime.stream_mode,
            "link_enabled": runtime.sender.link_enabled,
            "pending_count": counts["pending_count"],
            "total_sent_count": counts["total_sent_count"],
            "raw_count": counts["raw_count"],
        }

    @app.get("/api/egress-proof")
    async def egress_proof(limit: int = Query(default=40, ge=1, le=200)) -> Dict[str, object]:
        rows = await runtime.storage.get_egress_proof_rows(limit=limit)
        proof: List[Dict[str, object]] = []
        for row in rows:
            raw_event: Optional[Dict[str, object]] = None
            if row.get("raw_json"):
                try:
                    raw_event = InternalRawEvent.model_validate_json(
                        row["raw_json"]
                    ).model_dump(mode="json")
                except Exception:
                    raw_event = None
            wire_json = row.get("audit_payload_json") or row.get("payload_json")
            egress_event: Optional[Dict[str, object]] = None
            if wire_json:
                from shared.contracts import EgressMetadataPayload

                try:
                    egress_event = EgressMetadataPayload.model_validate_json(
                        wire_json
                    ).model_dump(mode="json")
                except Exception:
                    egress_event = None
            redaction_summary = None
            if row.get("redaction_summary_json"):
                try:
                    redaction_summary = json.loads(row["redaction_summary_json"])
                except Exception:
                    redaction_summary = None
            proof.append(
                {
                    "payload_id": row["payload_id"],
                    "raw_id": row["raw_id"],
                    "status": row["status"],
                    "retry_count": row["retry_count"],
                    "created_utc": row["created_utc"],
                    "sent_utc": row["sent_utc"],
                    "egress_sent_utc": (
                        egress_event or {}
                    ).get("egress_sent_utc"),
                    "is_backlog_replay": (
                        egress_event or {}
                    ).get("is_backlog_replay"),
                    "payload_sha256": row["payload_sha256"],
                    "raw": raw_event,
                    "egress": egress_event,
                    "redaction_summary": redaction_summary,
                }
            )
        return {"count": len(proof), "rows": proof}

    @app.get("/api/sent-ids")
    async def sent_ids() -> Dict[str, object]:
        ids = await runtime.storage.get_sent_payload_ids()
        return {"count": len(ids), "payload_ids": ids}

    @app.post("/control/toggle-link")
    async def toggle_link() -> Dict[str, object]:
        runtime.sender.link_enabled = not runtime.sender.link_enabled
        return {"link_enabled": runtime.sender.link_enabled}

    @app.post("/api/ingest-raw")
    async def ingest_raw(raw: InternalRawEvent) -> Dict[str, str]:
        payload_id = await runtime.handle_raw(raw)
        return {"payload_id": payload_id}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "collector.main:app",
        host="0.0.0.0",
        port=int(_env("COLLECTOR_PORT", "4001")),
    )
