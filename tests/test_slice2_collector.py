"""Slice 2 automated proof suite: Box 1 collector + mock chaos stream.

Covers the six mandated behaviours (a)-(f):
  a) secrets stay in raw_telemetry only; egress outbox/audit are clean
  b) cutting the SaaS link buffers events with zero loss
  c) restoring drains everything, stamps T2, flags backlog replay, audits
     SHA-256 and fires an immediate sync heartbeat on drain-to-zero
  d) raw retention pruning deletes only expired rows
  e) every mock-stream chaos scenario answers 200 with valid events
  f) live adapter collects real host telemetry and the normalizer maps aliases
"""

from __future__ import annotations

import asyncio
import socket
from datetime import timedelta
from hashlib import sha256
from typing import Callable, List

import httpx
from fastapi.testclient import TestClient

from collector.adapter import collect_live_host_events, normalize_external_event
from collector.scrubber import LocalScrubber
from collector.sender import EgressSender
from collector.storage import CollectorStorage
from mock_stream import stream_server as ss
from shared.contracts import (
    InternalRawEvent,
    Metrics,
    SourceType,
    parse_utc_iso,
    utc_now_iso,
)

TENANT = "bank-a"
REGION = "ap-south-1"
COLLECTOR_ID = "col-blr-01"
TOKEN = "tok-bank-a-blr"
SALT = "unit-test-salt"


def _iso_minus(seconds: float) -> str:
    return (
        (parse_utc_iso(utc_now_iso()) - timedelta(seconds=seconds))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _make_raw(
    *,
    hostname: str = "pay-db-01.internal",
    ip: str = "10.20.4.15",
    log_line: str | None = None,
) -> InternalRawEvent:
    return InternalRawEvent(
        real_hostname=hostname,
        real_ip=ip,
        source_type=SourceType.SERVER,
        metrics=Metrics(
            cpu_pct=41.5,
            memory_pct=63.0,
            disk_pct=55.0,
            service_up=True,
            latency_ms=12.5,
        ),
        raw_log_line=log_line,
    )


def _recording_client(calls: List[httpx.Request], *, fail_ingest: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if fail_ingest and "/api/v1/ingest/" in request.url.path:
            return httpx.Response(503, json={"error": "saas unavailable"})
        return httpx.Response(200, json={"accepted": True})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# a) secrets live in raw_telemetry only
# ---------------------------------------------------------------------------


def test_a_secrets_stay_local_egress_is_clean(tmp_path) -> None:
    async def run() -> None:
        storage = CollectorStorage(db_path=str(tmp_path / "a.db"))
        await storage.init_db()
        try:
            scrubber = LocalScrubber(local_hmac_salt=SALT)
            raw = _make_raw(
                log_line=(
                    "callback trace token=sk_live_abc123 password=hunter2xyz "
                    "src_ip=10.20.4.15"
                )
            )
            payload, scan = scrubber.scrub_to_egress(
                raw, tenant_id=TENANT, region=REGION, collector_id=COLLECTOR_ID
            )
            await storage.save_raw_and_queue(
                raw, payload, redacted_preview=scan.redacted_preview
            )

            calls: List[httpx.Request] = []
            sender = EgressSender(
                storage,
                tenant_id=TENANT,
                region=REGION,
                collector_id=COLLECTOR_ID,
                saas_base_url="https://saas.test",
                collector_token=TOKEN,
                client=_recording_client(calls),
            )
            try:
                assert await sender.send_pending_once() == 1
            finally:
                await sender.aclose()

            rows = await storage.get_egress_proof_rows()
            assert len(rows) == 1
            row = rows[0]

            # The raw row trapped locally still carries every secret.
            raw_blob = row["raw_json"]
            assert "sk_live_abc123" in raw_blob
            assert "hunter2xyz" in raw_blob
            assert "10.20.4.15" in raw_blob
            assert "pay-db-01.internal" in raw_blob

            # Neither the outbox payload nor the audited wire payload leaks.
            for blob_key in ("payload_json", "audit_payload_json"):
                blob = row[blob_key] or ""
                assert "sk_live_abc123" not in blob, blob_key
                assert "hunter2xyz" not in blob, blob_key
                assert "10.20.4.15" not in blob, blob_key
                assert "pay-db-01.internal" not in blob, blob_key

            # The bytes that actually hit the HTTP wire are equally clean and
            # carry the collector token header.
            wire_body = calls[0].content.decode("utf-8")
            for marker in ("sk_live_abc123", "hunter2xyz", "10.20.4.15",
                           "pay-db-01.internal"):
                assert marker not in wire_body
            assert calls[0].headers.get("X-Collector-Token") == TOKEN

            # Audit snapshot hashes the exact serialized wire payload.
            digest = sha256(
                (row["audit_payload_json"] or "").encode("utf-8")
            ).hexdigest()
            assert row["payload_sha256"] == digest
        finally:
            await storage.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# b) link cut buffers cleanly
# ---------------------------------------------------------------------------


def test_b_link_cut_buffers_ten_events(tmp_path) -> None:
    async def run() -> None:
        storage = CollectorStorage(db_path=str(tmp_path / "b.db"))
        await storage.init_db()
        try:
            scrubber = LocalScrubber(local_hmac_salt=SALT)
            calls: List[httpx.Request] = []
            sender = EgressSender(
                storage,
                tenant_id=TENANT,
                region=REGION,
                collector_id=COLLECTOR_ID,
                saas_base_url="https://saas.test",
                collector_token=TOKEN,
                client=_recording_client(calls),
            )
            sender.link_enabled = False  # hard SaaS outage
            try:
                for i in range(10):
                    raw = _make_raw(log_line=f"synthetic event {i}")
                    payload, scan = scrubber.scrub_to_egress(
                        raw,
                        tenant_id=TENANT,
                        region=REGION,
                        collector_id=COLLECTOR_ID,
                    )
                    await storage.save_raw_and_queue(
                        raw, payload, redacted_preview=scan.redacted_preview
                    )
                assert await sender.send_pending_once() == 0
            finally:
                await sender.aclose()

            counts = await storage.get_counts()
            assert counts["pending_count"] == 10
            assert counts["total_sent_count"] == 0
            assert calls == []  # zero HTTP attempts while the link is cut
        finally:
            await storage.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# c) restore drains with T2 stamping, backlog flag, audit + instant heartbeat
# ---------------------------------------------------------------------------


def test_c_restore_drains_ten_with_backlog_and_heartbeat(tmp_path) -> None:
    async def run() -> None:
        storage = CollectorStorage(db_path=str(tmp_path / "c.db"))
        await storage.init_db()
        try:
            scrubber = LocalScrubber(local_hmac_salt=SALT)
            calls: List[httpx.Request] = []
            sender = EgressSender(
                storage,
                tenant_id=TENANT,
                region=REGION,
                collector_id=COLLECTOR_ID,
                saas_base_url="https://saas.test",
                collector_token=TOKEN,
                client=_recording_client(calls),
            )
            sender.link_enabled = False
            try:
                for i in range(10):
                    raw = _make_raw(log_line=f"buffered during outage {i}")
                    # Collected 10s ago: older than the 5s backlog threshold.
                    payload, scan = scrubber.scrub_to_egress(
                        raw,
                        tenant_id=TENANT,
                        region=REGION,
                        collector_id=COLLECTOR_ID,
                        collected_time_utc=_iso_minus(10.0),
                    )
                    await storage.save_raw_and_queue(
                        raw, payload, redacted_preview=scan.redacted_preview
                    )
                assert await sender.send_pending_once() == 0

                sender.link_enabled = True  # restore the link
                sent = await sender.send_pending_once()
                assert sent == 10
            finally:
                await sender.aclose()

            counts = await storage.get_counts()
            assert counts["pending_count"] == 0
            assert counts["total_sent_count"] == 10

            rows = await storage.get_egress_proof_rows(limit=50)
            assert len(rows) == 10
            sent_ids = await storage.get_sent_payload_ids()
            assert len(sent_ids) == 10 and len(set(sent_ids)) == 10  # zero loss

            for row in rows:
                assert row["status"] == "SENT"
                assert row["sent_utc"] is not None
                digest = sha256(
                    (row["audit_payload_json"] or "").encode("utf-8")
                ).hexdigest()
                assert row["payload_sha256"] == digest
                from shared.contracts import EgressMetadataPayload

                wire = EgressMetadataPayload.model_validate_json(
                    row["audit_payload_json"]
                )
                # T2 stamped at actual send time (within 30s of now).
                t2 = parse_utc_iso(wire.egress_sent_utc)
                now = parse_utc_iso(utc_now_iso())
                assert abs((now - t2).total_seconds()) < 30.0
                # Collected >5s before T2 => flagged as backlog replay.
                assert wire.is_backlog_replay is True

            # Immediate sync heartbeat fired right after the drain to zero.
            ingest_idx = next(
                i for i, c in enumerate(calls) if "/api/v1/ingest/" in c.url.path
            )
            heartbeat_idx = next(
                i for i, c in enumerate(calls) if "/api/v1/heartbeat/" in c.url.path
            )
            assert heartbeat_idx > ingest_idx
            beat_body = calls[heartbeat_idx].content.decode("utf-8")
            assert '"outbox_pending_count":0' in beat_body.replace(" ", "")
            assert '"total_sent_count":10' in beat_body.replace(" ", "")
        finally:
            await storage.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# d) raw retention pruning
# ---------------------------------------------------------------------------


def test_d_prune_expired_raw_keeps_live_rows(tmp_path) -> None:
    async def run() -> None:
        storage = CollectorStorage(db_path=str(tmp_path / "d.db"))
        await storage.init_db()
        try:
            scrubber = LocalScrubber(local_hmac_salt=SALT)
            for i, expires in enumerate(
                (_iso_minus(60.0), _iso_minus(1.0), _iso_minus(-3600.0))
            ):
                raw = _make_raw(log_line=f"row {i}")
                payload, scan = scrubber.scrub_to_egress(
                    raw, tenant_id=TENANT, region=REGION, collector_id=COLLECTOR_ID
                )
                await storage.save_raw_and_queue(
                    raw,
                    payload,
                    redacted_preview=scan.redacted_preview,
                    expires_at_utc=expires,
                )

            deleted = await storage.prune_expired_raw(utc_now_iso())
            assert deleted == 2  # the two expired rows
            counts = await storage.get_counts()
            assert counts["raw_count"] == 1  # the future-expiry row survives
            rows = await storage.get_egress_proof_rows()
            assert rows[0]["raw_json"].find("row 2") >= 0
        finally:
            await storage.close()

    asyncio.run(run())


# ---------------------------------------------------------------------------
# e) mock chaos stream scenarios
# ---------------------------------------------------------------------------


def test_e_chaos_scenarios_return_200_with_valid_events() -> None:
    with TestClient(ss.app) as client:
        for scenario in ss.SCENARIOS:
            resp = client.post(f"/chaos/{scenario}", params={"site": "bank-a"})
            assert resp.status_code == 200, scenario
            body = resp.json()
            assert body["status"] == "ok", scenario
            assert body["emitted"], scenario
            for event in body["emitted"]:
                InternalRawEvent.model_validate(event)

        # secret: the raw log carries all three judge markers
        secret = client.post("/chaos/secret", params={"site": "bank-a"}).json()
        log = secret["emitted"][0]["raw_log_line"]
        assert "sk_live_98a7sd98a7sd" in log
        assert "password=hunter2xyz" in log
        assert "10.20.4.15" in log

        # failed_logins: a burst of 14 failed-login auth events
        burst = client.post("/chaos/failed_logins", params={"site": "bank-a"}).json()
        assert len(burst["emitted"]) == 14
        assert all(e["failed_login_event"] for e in burst["emitted"])
        assert burst["emitted"][0]["real_hostname"] == "pay-db-01.internal"

        # duplicate_payload: two events share one forced_payload_id
        dup = client.post(
            "/chaos/duplicate_payload", params={"site": "bank-a"}
        ).json()
        assert len(dup["emitted"]) == 2
        forced_ids = {e["forced_payload_id"] for e in dup["emitted"]}
        assert len(forced_ids) == 1
        assert None not in forced_ids

        # out_of_order: event_time_utc ~90 seconds in the past
        ooo = client.post("/chaos/out_of_order", params={"site": "bank-a"}).json()
        event_ts = parse_utc_iso(ooo["emitted"][0]["event_time_utc"])
        age = (parse_utc_iso(utc_now_iso()) - event_ts).total_seconds()
        assert 80.0 <= age <= 100.0
        assert ooo["emitted"][0]["metrics"]["latency_ms"] == 180.0

        # second site works too, and unknown scenario/site are rejected
        assert client.post(
            "/chaos/latency_spike", params={"site": "hospital-b"}
        ).status_code == 200
        assert client.post("/chaos/does-not-exist").status_code == 404
        assert client.post("/chaos/secret", params={"site": "nope"}).status_code == 404


def test_e_ws_stream_hospital_b_delivers_valid_json_frames() -> None:
    # Regression: emit() queues dict payloads onto the ws queues; feeding them
    # straight into send_text crashed with AttributeError ('dict' object has
    # no attribute 'encode') the moment a WS client connected.
    with TestClient(ss.app) as client:
        with client.websocket_connect("/ws/stream/hospital-b") as ws:
            frame = ws.receive_json()
            event = InternalRawEvent.model_validate(frame)
            assert event.real_hostname in {
                p.real_hostname for p in ss.SITES["hospital-b"].sources
            }
            assert event.metrics is not None


# ---------------------------------------------------------------------------
# f) live adapter + normalizer
# ---------------------------------------------------------------------------


def test_f_live_adapter_collects_real_telemetry(tmp_path) -> None:
    # Probe a surely-closed local port: offline-tolerant, fast, deterministic.
    host_event, uplink_event = asyncio.run(
        collect_live_host_events("127.0.0.1", 1, source_timezone="Asia/Kolkata")
    )

    assert host_event.metrics.cpu_pct is not None
    assert host_event.metrics.memory_pct is not None
    assert host_event.metrics.disk_pct is not None
    assert host_event.real_hostname == socket.gethostname()
    assert host_event.real_ip  # LAN IPv4 or the 127.0.0.1 fallback
    assert host_event.source_type == SourceType.SERVER
    assert host_event.upstream_device_real_name == "wan-uplink-1.1.1.1"
    assert host_event.metrics.service_up is True

    assert uplink_event.source_type == SourceType.NETWORK_DEVICE
    assert uplink_event.real_hostname == "wan-uplink-1.1.1.1"
    # Probe to a closed port must fail gracefully, not raise.
    assert uplink_event.metrics.connectivity == "down"

    # The scrubber must strip the real hostname and IP from the egress copy.
    scrubber = LocalScrubber(local_hmac_salt=SALT)
    payload, _scan = scrubber.scrub_to_egress(
        host_event, tenant_id=TENANT, region=REGION, collector_id=COLLECTOR_ID
    )
    blob = payload.model_dump_json()
    assert socket.gethostname() not in blob
    assert host_event.real_ip not in blob


def test_f_normalize_external_event_maps_aliases() -> None:
    event = normalize_external_event(
        {
            "ts": "2026-11-21T00:00:00.000Z",
            "host": "web-01.internal",
            "ip": "10.1.2.3",
            "cpu": 77.5,
            "mem": 66.5,
            "disk": 55.5,
            "latency": 42.5,
            "packet_loss": 1.5,
            "message": "upstream slow",
        }
    )
    assert isinstance(event, InternalRawEvent)
    assert event.event_time_utc == "2026-11-21T00:00:00.000Z"
    assert event.real_hostname == "web-01.internal"
    assert event.real_ip == "10.1.2.3"
    assert event.metrics.cpu_pct == 77.5
    assert event.metrics.memory_pct == 66.5
    assert event.metrics.disk_pct == 55.5
    assert event.metrics.latency_ms == 42.5
    assert event.metrics.packet_loss_pct == 1.5
    assert event.raw_log_line == "upstream slow"
