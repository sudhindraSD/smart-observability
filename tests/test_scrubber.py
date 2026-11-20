"""Slice 1 verification: Tier 1 scrubbing, pseudonymization, and the
secret-safe FastAPI 422 handler."""

import random
import string

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from collector.scrubber import LocalScrubber, looks_random, scan_raw_text
from shared.contracts import (
    ConnectivityState,
    IngestBatchRequest,
    InternalRawEvent,
    Metrics,
    SecurityRisk,
    Severity,
    SourceType,
)
from shared.safe_errors import install_safe_validation_handler

HEX32 = "".join(random.Random(7).choices("0123456789abcdef", k=32))
# Spec-pinned 12-char base62 fixture. (Python 3.13's Random(42).choices()
# actually draws "NbrnTP3fAbnF" -- covered below as DERIVED12 -- so the spec's
# literal is kept as the reference token.)
BARE12 = "OhbVrpoiVgRV"
DERIVED12 = "".join(random.Random(42).choices(string.ascii_letters + string.digits, k=12))

LOG_LINE = (
    "auth failure user=admin password=hunter2 "
    f"key={HEX32} token=sk_live_abc123 session={BARE12} "
    "contact=ops@example.com from 10.20.30.40"
)


def _raw_event(**kwargs) -> InternalRawEvent:
    return InternalRawEvent(
        real_hostname="db-primary-01",
        real_ip="10.20.30.40",
        source_type=SourceType.SERVER,
        metrics=Metrics(
            cpu_pct=31.0,
            memory_pct=55.0,
            disk_pct=61.0,
            service_up=True,
            bandwidth_mbps=310.0,
            latency_ms=13.0,
            packet_loss_pct=0.2,
            connectivity=ConnectivityState.UP,
        ),
        raw_log_line=LOG_LINE,
        **kwargs,
    )


@pytest.mark.parametrize(
    ("sample", "expected_type"),
    [
        ("sk_live_abc123", "api_key"),
        (BARE12, "bare_token"),
        (DERIVED12, "bare_token"),
        (HEX32, "hex_key"),
        ("password=abc123", "credential"),
    ],
)
def test_known_secret_samples_are_detected(sample, expected_type):
    scan = scan_raw_text(f"boot ok {sample} done")
    assert scan.secrets_scrubbed_count >= 1
    assert expected_type in scan.secret_types_detected
    assert sample not in scan.redacted_preview
    assert "[REDACTED]" in scan.redacted_preview


@pytest.mark.parametrize("clean", ["AuthenticationService", "status=200 latency=12ms"])
def test_negative_controls_not_flagged(clean):
    scan = scan_raw_text(clean)
    assert scan.secrets_scrubbed_count == 0
    assert scan.secret_types_detected == []
    assert scan.redacted_preview == clean


def test_looks_random_thresholds():
    assert looks_random(BARE12)
    assert not looks_random("AuthenticationService")
    assert not looks_random("short")
    assert not looks_random("aaaaaaaaaaaa")


def test_scan_none_and_empty():
    assert scan_raw_text(None).redacted_preview == ""
    assert scan_raw_text(None).secrets_scrubbed_count == 0
    assert scan_raw_text("").secrets_scrubbed_count == 0


def test_scrub_to_egress_drops_all_sensitive_fields():
    scrubber = LocalScrubber("unit-test-salt")
    payload, scan = scrubber.scrub_to_egress(
        _raw_event(), tenant_id="acme", region="ap-mumbai", collector_id="col-1"
    )

    assert scan.secrets_scrubbed_count >= 5
    blob = payload.model_dump_json()
    for leaked in (
        "db-primary-01",
        "10.20.30.40",
        "hunter2",
        "sk_live_abc123",
        BARE12,
        HEX32,
        "ops@example.com",
        "password=",
        "auth failure",
    ):
        assert leaked not in blob, f"{leaked!r} leaked into egress payload"

    assert payload.egress_sent_utc is None
    assert payload.is_backlog_replay is None
    assert payload.redaction_audit.secrets_scrubbed_count == scan.secrets_scrubbed_count
    assert payload.redaction_audit.pseudonymized is True
    assert "real_hostname" in payload.redaction_audit.raw_fields_dropped
    assert "raw_log_line" in payload.redaction_audit.raw_fields_dropped
    assert payload.source_id.startswith("src-")
    assert payload.source_type == SourceType.SERVER
    assert payload.tenant_id == "acme"


def test_forced_payload_id_preserved_and_sender_fields_unset():
    scrubber = LocalScrubber("unit-test-salt")
    payload, _ = scrubber.scrub_to_egress(
        _raw_event(forced_payload_id="forced-abc-123"), "t", "r", "c"
    )
    assert payload.payload_id == "forced-abc-123"

    payload2, _ = scrubber.scrub_to_egress(_raw_event(), "t", "r", "c")
    assert payload2.payload_id and payload2.payload_id != "forced-abc-123"


def test_pseudonymize_deterministic_and_prefixed():
    scrubber = LocalScrubber("salt-A")
    a1 = scrubber.pseudonymize("db-primary-01")
    a2 = scrubber.pseudonymize("db-primary-01")
    assert a1 == a2
    assert a1.startswith("src-") and len(a1) == len("src-") + 6

    net = scrubber.pseudonymize("core-switch-1", is_network=True)
    assert net.startswith("net-") and len(net) == len("net-") + 6

    other = LocalScrubber("salt-B").pseudonymize("db-primary-01")
    assert other != a1


def test_upstream_pseudonymized_with_same_salt():
    scrubber = LocalScrubber("salt-A")
    payload, _ = scrubber.scrub_to_egress(
        _raw_event(upstream_device_real_name="core-switch-1"), "t", "r", "c"
    )
    assert payload.upstream_source_id == scrubber.pseudonymize(
        "core-switch-1", is_network=True
    )
    assert payload.upstream_source_id.startswith("net-")
    assert "core-switch-1" not in payload.model_dump_json()


def test_alert_context_never_leaks_raw_credentials():
    scrubber = LocalScrubber("unit-test-salt")
    payload, _ = scrubber.scrub_to_egress(
        _raw_event(failed_login_event=True), "t", "r", "c"
    )
    context = payload.alert_context
    for banned in (
        "hunter2",
        "sk_live",
        BARE12,
        HEX32,
        "db-primary-01",
        "admin",
        "password",
        "auth failure",
    ):
        assert banned not in context
    assert context.startswith("Local watch on src-")
    assert payload.event_category == "security"
    assert payload.security_summary.failed_logins_1m >= 1


def test_security_window_counts_and_escalates():
    scrubber = LocalScrubber("unit-test-salt")
    for _ in range(3):
        payload, _ = scrubber.scrub_to_egress(
            _raw_event(failed_login_event=True), "t", "r", "c"
        )
    assert payload.security_summary.failed_logins_1m == 3
    assert payload.security_summary.security_risk == SecurityRisk.LOW

    for _ in range(22):
        payload, _ = scrubber.scrub_to_egress(
            _raw_event(failed_login_event=True), "t", "r", "c"
        )
    assert payload.security_summary.failed_logins_1m == 25
    assert payload.security_summary.security_risk == SecurityRisk.CRITICAL
    assert payload.severity == Severity.CRITICAL


BAD_BODY = {"collector_id": "c1", "batch": [], "extra_field": "hunter2xyz"}


def _app(safe: bool) -> FastAPI:
    app = FastAPI()
    if safe:
        install_safe_validation_handler(app)

    @app.post("/ingest")
    async def ingest(req: IngestBatchRequest) -> dict:
        return {"ok": True, "count": len(req.batch)}

    return app


def test_default_fastapi_422_echoes_rejected_secret():
    with TestClient(_app(safe=False)) as client:
        resp = client.post("/ingest", json=BAD_BODY)
    assert resp.status_code == 422
    assert "hunter2xyz" in resp.text


def test_safe_validation_handler_strips_input():
    with TestClient(_app(safe=True)) as client:
        resp = client.post("/ingest", json=BAD_BODY)
    assert resp.status_code == 422
    assert "hunter2xyz" not in resp.text
    errors = resp.json()
    assert isinstance(errors, list) and errors
    for err in errors:
        assert set(err) == {"type", "loc", "msg"}
        assert "hunter2xyz" not in str(err["msg"])


@pytest.mark.parametrize(
    ("length", "min_recall"), [(12, 0.85), (20, 0.88)]
)
def test_bare_base62_recall(length, min_recall):
    rng = random.Random(1234 + length)
    trials = 200
    hits = 0
    for _ in range(trials):
        token = "".join(rng.choices(string.ascii_letters + string.digits, k=length))
        if scan_raw_text(f"x {token} y").secrets_scrubbed_count >= 1:
            hits += 1
    assert hits / trials >= min_recall, f"recall {hits}/{trials} below {min_recall}"
