"""Slice 3 end-to-end validation: the 10 live judge scenarios against Box 2."""

import asyncio
import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from collector.scrubber import LocalScrubber
from saas.db import SaasDatabase
from saas.main import create_app
from saas.remediation import build_remediation_plan, evaluate_policy
from saas.watchdog import Watchdog
from shared.contracts import CollectorHeartbeat, InternalRawEvent, Metrics, ThresholdConfig, parse_utc_iso

WHO = {
    "bank-a": {"region": "ap-south-1", "collector": "col-blr-01", "token": "tok-bank-a-blr"},
    "hospital-b": {"region": "eu-west-1", "collector": "col-fra-01", "token": "tok-hosp-b-fra"},
}

# Fake scrub-target secret, split so no literal in this file matches a real key pattern.
FAKE_API_KEY = "sk_live_" + "abcdefgh1234567890"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _iso_minus(seconds: float) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(seconds=seconds)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _metrics(**overrides) -> Metrics:
    base = {
        "cpu_pct": 41.5,
        "memory_pct": 63.0,
        "disk_pct": 55.0,
        "service_up": True,
        "bandwidth_mbps": 300.0,
        "latency_ms": 12.5,
        "packet_loss_pct": 0.2,
        "connectivity": "up",
    }
    base.update(overrides)
    return Metrics(**base)


def _payload(**overrides) -> dict:
    now = _utcnow()
    payload = {
        "payload_id": f"pl-{uuid.uuid4().hex[:12]}",
        "tenant_id": "bank-a",
        "region": "ap-south-1",
        "collector_id": "col-blr-01",
        "source_id": "src-web-01",
        "source_type": "server",
        "upstream_source_id": None,
        "event_time_utc": now,
        "source_timezone": "Asia/Kolkata",
        "collected_time_utc": now,
        "metrics": _metrics().model_dump(),
        "security_summary": {},
        "redaction_audit": {"raw_fields_dropped": [], "secret_types_detected": []},
    }
    payload.update(overrides)
    return payload


def _ingest(client: TestClient, who: str, payloads: list):
    w = WHO[who]
    return client.post(
        f"/api/v1/ingest/{w['region']}",
        headers={"X-Collector-Token": w["token"]},
        json={"collector_id": w["collector"], "batch": payloads},
    )


def _heartbeat(client: TestClient, who: str, total_sent: int = 0, **overrides):
    w = WHO[who]
    body = {
        "heartbeat_id": f"hb-{uuid.uuid4().hex[:8]}",
        "tenant_id": who,
        "region": w["region"],
        "collector_id": w["collector"],
        "sent_time_utc": _utcnow(),
        "total_sent_count": total_sent,
    }
    body.update(overrides)
    return client.post(
        f"/api/v1/heartbeat/{w['region']}",
        headers={"X-Collector-Token": w["token"]},
        json=body,
    )


def _login(client: TestClient, username: str) -> str:
    resp = client.post("/api/v1/auth/login", json={"username": username, "password": "demo123"})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def _auth(client: TestClient, username: str) -> dict:
    return {"Authorization": f"Bearer {_login(client, username)}"}


def _db_bytes(tmp_path, filename: str) -> str:
    blob = b""
    for suffix in ("", "-wal", "-shm"):
        path = tmp_path / (filename + suffix)
        if path.exists():
            blob += path.read_bytes()
    return blob.decode("latin-1")


def _scalar(db_path, sql: str, params=()):
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


def _expl(incident: dict) -> dict:
    expl = incident.get("explanation")
    if isinstance(expl, str):
        expl = json.loads(expl)
    return expl or {}


def _rem(incident: dict) -> dict:
    rem = incident.get("remediation")
    if isinstance(rem, str):
        rem = json.loads(rem)
    return rem or {}


def _warm_payloads(source_id: str = "src-web-01", count: int = 20, **metric_overrides) -> list:
    return [
        _payload(
            source_id=source_id,
            event_time_utc=_iso_minus(21 - i),
            metrics=_metrics(**metric_overrides).model_dump() if metric_overrides else _metrics().model_dump(),
        )
        for i in range(count)
    ]


def _make_client(tmp_path):
    app = create_app(data_dir=str(tmp_path), disable_watchdog=True)
    return TestClient(app)


# 1) Secret scrub + 422 leak guard -------------------------------------------------


def test_01_secret_scrub_and_422_leak_guard(tmp_path):
    client = _make_client(tmp_path)
    with client:
        scrubber = LocalScrubber("unit-test-salt")
        raw = InternalRawEvent(
            real_hostname="pay-db-01.internal",
            raw_log_line=f"GET /admin api_key={FAKE_API_KEY} password=hunter2",
            metrics=_metrics(),
        )
        payload, _scan = scrubber.scrub_to_egress(raw, "bank-a", "ap-south-1", "col-blr-01")
        resp = _ingest(client, "bank-a", [payload.model_dump()])
        assert resp.status_code == 200, resp.text
        assert resp.json()["accepted"] == 1

        blob = _db_bytes(tmp_path, "saas_ap_south_1.db")
        for secret in (FAKE_API_KEY, "hunter2", "pay-db-01.internal", "10.20.4.15"):
            assert secret not in blob, f"leaked into regional DB: {secret}"

        leak = _payload()
        leak["raw_log_line"] = "password=hunter2xyz"
        resp = client.post(
            "/api/v1/ingest/ap-south-1",
            headers={"X-Collector-Token": "tok-bank-a-blr"},
            json={"collector_id": "col-blr-01", "batch": [leak]},
        )
        assert resp.status_code == 422, resp.text
        assert "hunter2xyz" not in resp.text


# 2) Outage backlog replay (Amendment A6) ------------------------------------------


def test_02_backlog_replay_never_alerts(tmp_path):
    client = _make_client(tmp_path)
    with client:
        assert _heartbeat(client, "bank-a", total_sent=10).status_code == 200
        batch = [
            _payload(
                source_id=f"src-bl-{i:02d}",
                event_time_utc=_iso_minus(3600),
                is_backlog_replay=True,
                metrics=_metrics(latency_ms=250.0, packet_loss_pct=4.0).model_dump(),
            )
            for i in range(10)
        ]
        resp = _ingest(client, "bank-a", batch)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["accepted"] == 10
        assert body["duplicates_blocked"] == 0
        assert body["incidents_touched"] == 0

        sla = client.get("/api/v1/sla-metrics", headers=_auth(client, "bank-a")).json()
        assert sla["total_sent_count"] == 10
        assert sla["total_received_count"] == 10
        assert sla["lost_count"] == 0
        assert sla["duplicates_blocked_count"] == 0
        assert sla["backlog_replayed_count"] == 10
        assert sla["ingest_latency_p95_sec"] is None
        assert sla["alert_latency_latest_sec"] is None
        assert sla["alert_latency_p95_sec"] is None

        overview = client.get("/api/v1/overview", headers=_auth(client, "bank-a")).json()
        assert overview["sources"] == []
        assert overview["incidents"] == []

        assert (
            _scalar(tmp_path / "saas_ap_south_1.db", "SELECT COUNT(*) FROM telemetry_events WHERE is_backlog_replay = 1")
            == 10
        )


# 3) Repeated failed logins ---------------------------------------------------------


def test_03_failed_logins_raise_security_incident_without_raw_logs(tmp_path):
    client = _make_client(tmp_path)
    with client:
        scrubber = LocalScrubber("unit-test-salt")
        payloads = []
        for i in range(14):
            raw = InternalRawEvent(
                real_hostname="auth-gw-01.internal",
                raw_log_line=f"Failed password for invalid user admin from 10.20.4.15 port {4200 + i} ssh2",
                failed_login_event=True,
                metrics=_metrics(),
            )
            egress, _scan = scrubber.scrub_to_egress(raw, "bank-a", "ap-south-1", "col-blr-01")
            payloads.append(egress.model_dump())

        resp = _ingest(client, "bank-a", payloads)
        assert resp.status_code == 200, resp.text
        assert resp.json()["accepted"] == 14
        assert resp.json()["incidents_touched"] == 3

        incidents = client.get("/api/v1/incidents", headers=_auth(client, "bank-a")).json()["incidents"]
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident["merged_alert_count"] == 3
        assert incident["severity"] == "high"
        assert _rem(incident)["proposed_action"] == "SIMULATE_BLOCK_SOURCE_AUTH"

        blob = _db_bytes(tmp_path, "saas_ap_south_1.db")
        for secret in ("invalid user admin", "10.20.4.15", "Failed password"):
            assert secret not in blob, f"raw auth log leaked: {secret}"


# 4) Network latency spike -----------------------------------------------------------


def test_04_latency_spike_explainable_anomaly(tmp_path):
    client = _make_client(tmp_path)
    with client:
        resp = _ingest(client, "bank-a", _warm_payloads())
        assert resp.status_code == 200, resp.text
        assert resp.json()["incidents_touched"] == 0

        spike = _payload(
            event_time_utc=_iso_minus(0.5),
            metrics=_metrics(latency_ms=185.0, packet_loss_pct=4.2).model_dump(),
        )
        resp = _ingest(client, "bank-a", [spike])
        assert resp.json()["incidents_touched"] == 1

        incidents = client.get("/api/v1/incidents", headers=_auth(client, "bank-a")).json()["incidents"]
        assert len(incidents) == 1
        expl = _expl(incidents[0])
        assert expl["max_z_score"] >= 4.0
        weights = [signal["weight_pct"] for signal in expl["contributing_signals"]]
        assert sum(weights) == 100
        rem = _rem(incidents[0])
        assert rem["proposed_action"] == "SIMULATE_FAILOVER_UPLINK"
        assert rem["state"] == "AWAITING_APPROVAL"


# 5) CPU/memory baseline deviation ----------------------------------------------------


def test_05_cpu_memory_spike_robust_zscore(tmp_path):
    client = _make_client(tmp_path)
    with client:
        resp = _ingest(client, "bank-a", _warm_payloads())
        assert resp.status_code == 200, resp.text

        spike = _payload(
            event_time_utc=_iso_minus(0.5),
            metrics=_metrics(cpu_pct=92.0, memory_pct=88.0).model_dump(),
        )
        resp = _ingest(client, "bank-a", [spike])
        assert resp.json()["incidents_touched"] == 1

        incidents = client.get("/api/v1/incidents", headers=_auth(client, "bank-a")).json()["incidents"]
        assert len(incidents) == 1
        expl = _expl(incidents[0])
        assert expl["max_z_score"] >= 4.0
        weights = [signal["weight_pct"] for signal in expl["contributing_signals"]]
        assert sum(weights) == 100
        assert _rem(incidents[0])["proposed_action"] == "SIMULATE_SCALE_OR_THROTTLE_WORKLOAD"


# 6) Cascading router + downstream correlation ----------------------------------------


def test_06_cascade_correlation_single_incident(tmp_path):
    client = _make_client(tmp_path)
    with client:
        for source_id, source_type, upstream in (
            ("net-rtr-01", "network_device", None),
            ("src-app-01", "server", "net-rtr-01"),
            ("src-app-02", "server", "net-rtr-01"),
        ):
            batch = [
                _payload(
                    source_id=source_id,
                    source_type=source_type,
                    upstream_source_id=upstream,
                    event_time_utc=_iso_minus(21 - i),
                )
                for i in range(20)
            ]
            resp = _ingest(client, "bank-a", batch)
            assert resp.json()["incidents_touched"] == 0

        spike_metrics = _metrics(latency_ms=185.0, packet_loss_pct=4.2).model_dump()
        resp = _ingest(
            client,
            "bank-a",
            [_payload(source_id="net-rtr-01", source_type="network_device", event_time_utc=_iso_minus(1.8), metrics=spike_metrics)],
        )
        assert resp.json()["incidents_touched"] == 1

        resp = _ingest(
            client,
            "bank-a",
            [_payload(source_id="src-app-01", upstream_source_id="net-rtr-01", event_time_utc=_iso_minus(1.5), metrics=spike_metrics)],
        )
        assert resp.json()["incidents_touched"] == 1

        resp = _ingest(
            client,
            "bank-a",
            [_payload(source_id="src-app-02", upstream_source_id="net-rtr-01", event_time_utc=_iso_minus(1.2), metrics=spike_metrics)],
        )
        assert resp.json()["incidents_touched"] == 1

        incidents = client.get("/api/v1/incidents", headers=_auth(client, "bank-a")).json()["incidents"]
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident["root_cause_source_id"] == "net-rtr-01"
        assert incident["merged_alert_count"] == 3
        assert set(incident["affected_source_ids"]) == {"net-rtr-01", "src-app-01", "src-app-02"}
        assert _expl(incident)["recommended_action"] == ""


# 7) Deduplication & out-of-order protection ------------------------------------------


def test_07_dedup_and_out_of_order(tmp_path):
    client = _make_client(tmp_path)
    with client:
        resp = _ingest(client, "bank-a", _warm_payloads())
        assert resp.status_code == 200, resp.text

        original = _payload(payload_id="dup-payload-001", event_time_utc=_iso_minus(0.5))
        resp = _ingest(client, "bank-a", [original])
        assert resp.json()["accepted"] == 1

        resp = _ingest(client, "bank-a", [original])
        assert resp.json()["accepted"] == 0
        assert resp.json()["duplicates_blocked"] == 1

        late = _payload(
            payload_id="late-payload-001",
            event_time_utc=_iso_minus(90),
            metrics=_metrics(latency_ms=500.0, packet_loss_pct=50.0).model_dump(),
        )
        resp = _ingest(client, "bank-a", [late])
        assert resp.json()["accepted"] == 1
        assert resp.json()["incidents_touched"] == 0

        sla = client.get("/api/v1/sla-metrics", headers=_auth(client, "bank-a")).json()
        assert sla["duplicates_blocked_count"] == 1

        series = client.get(
            "/api/v1/sources/src-web-01/series", params={"limit": 120}, headers=_auth(client, "bank-a")
        ).json()
        assert series["count"] == 22
        times = [event["event_time_utc"] for event in series["events"]]
        assert times == sorted(times)
        assert series["events"][0]["payload_id"] == "late-payload-001"

        overview = client.get("/api/v1/overview", headers=_auth(client, "bank-a")).json()
        assert overview["sources"][0]["health_state"] == "Excellent"
        assert overview["incidents"] == []


# 8) Safe remediation lifecycle --------------------------------------------------------


def test_08_remediation_lifecycle(tmp_path):
    client = _make_client(tmp_path)
    with client:
        _ingest(client, "bank-a", _warm_payloads())
        _ingest(
            client,
            "bank-a",
            [_payload(event_time_utc=_iso_minus(0.5), metrics=_metrics(latency_ms=185.0, packet_loss_pct=4.2).model_dump())],
        )
        incident = client.get("/api/v1/incidents", headers=_auth(client, "bank-a")).json()["incidents"][0]
        incident_id = incident["incident_id"]
        rem = _rem(incident)
        assert rem["state"] == "AWAITING_APPROVAL"
        assert rem["policy_check_passed"] is True
        audit_len = len(rem["audit_trail"])

        resp = client.post(f"/api/v1/incidents/{incident_id}/approve", headers=_auth(client, "bank-a"))
        assert resp.status_code == 200, resp.text
        rem = _rem(resp.json())
        assert rem["state"] == "APPROVED_EXECUTED"
        assert len(rem["audit_trail"]) == audit_len + 1
        assert rem["audit_trail"][-1]["action"] == "approve"

        resp = client.post(f"/api/v1/incidents/{incident_id}/rollback", headers=_auth(client, "bank-a"))
        assert resp.status_code == 200, resp.text
        rem = _rem(resp.json())
        assert rem["state"] == "ROLLED_BACK"
        assert rem["audit_trail"][-1]["action"] == "rollback"

        resp = client.post(f"/api/v1/incidents/{incident_id}/rollback", headers=_auth(client, "bank-a"))
        assert resp.status_code == 409

    assert evaluate_policy("DROP_PRODUCTION_DB") == (False, "BLOCK_DESTRUCTIVE_ACTION")
    blocked = build_remediation_plan("DROP_PRODUCTION_DB", context={"incident_id": "inc-x"})
    assert blocked.policy_check_passed is False
    assert blocked.state == "POLICY_BLOCKED"


# 9) Strict multi-tenant & regional residency isolation --------------------------------


def test_09_multi_tenant_isolation(tmp_path):
    client = _make_client(tmp_path)
    with client:
        resp = _ingest(client, "bank-a", [_payload(source_id="src-bank-only")])
        assert resp.status_code == 200, resp.text
        resp = _ingest(
            client,
            "hospital-b",
            [_payload(source_id="src-hosp-only", tenant_id="hospital-b", region="eu-west-1", collector_id="col-fra-01")],
        )
        assert resp.status_code == 200, resp.text
        assert _heartbeat(client, "bank-a").status_code == 200
        assert _heartbeat(client, "hospital-b").status_code == 200

        bank_overview = client.get("/api/v1/overview", headers=_auth(client, "bank-a")).json()
        assert bank_overview["regional_db_file"].endswith("saas_ap_south_1.db")
        bank_blob = json.dumps(bank_overview)
        for foreign in ("hospital-b", "col-fra-01", "src-hosp-only"):
            assert foreign not in bank_blob

        hosp_overview = client.get("/api/v1/overview", headers=_auth(client, "hospital-b")).json()
        assert hosp_overview["regional_db_file"].endswith("saas_eu_west_1.db")
        hosp_blob = json.dumps(hosp_overview)
        for foreign in ("bank-a", "col-blr-01", "src-bank-only"):
            assert foreign not in hosp_blob

        # Cross-region ingest with bank-a token -> 403
        resp = client.post(
            "/api/v1/ingest/eu-west-1",
            headers={"X-Collector-Token": "tok-bank-a-blr"},
            json={"collector_id": "col-blr-01", "batch": [_payload()]},
        )
        assert resp.status_code == 403

        # Wrong-tenant payload with hospital-b token -> 403
        resp = client.post(
            "/api/v1/ingest/eu-west-1",
            headers={"X-Collector-Token": "tok-hosp-b-fra"},
            json={"collector_id": "col-fra-01", "batch": [_payload()]},
        )
        assert resp.status_code == 403

        ap_db = tmp_path / "saas_ap_south_1.db"
        eu_db = tmp_path / "saas_eu_west_1.db"
        for table in ("telemetry_events", "collectors", "sources_state", "incidents", "health_transitions"):
            assert _scalar(ap_db, f"SELECT COUNT(*) FROM {table} WHERE tenant_id = 'hospital-b'") == 0
            assert _scalar(eu_db, f"SELECT COUNT(*) FROM {table} WHERE tenant_id = 'bank-a'") == 0

        # WS: hospital-b JWT on /ws/bank-a must be closed with 1008
        bad_token = _login(client, "hospital-b")
        with pytest.raises(WebSocketDisconnect) as excinfo:
            with client.websocket_connect(f"/ws/bank-a?token={bad_token}") as ws:
                ws.receive_json()
        assert excinfo.value.code == 1008

        # Positive: bank-a JWT connects and receives its own telemetry frame
        good_token = _login(client, "bank-a")
        with client.websocket_connect(f"/ws/bank-a?token={good_token}") as ws:
            resp = _ingest(client, "bank-a", [_payload(source_id="src-ws-probe")])
            assert resp.status_code == 200, resp.text
            frame = ws.receive_json()
            assert frame["type"] == "telemetry"
            assert frame["data"]["source_id"] == "src-ws-probe"


# 10) Watchdog offline & stale-data detection ------------------------------------------


def test_10_watchdog_offline_and_stale_detection(tmp_path):
    async def scenario():
        db = SaasDatabase(data_dir=str(tmp_path))
        await db.init_db(
            seed_tenants=[
                {"tenant_id": "bank-a", "region": "ap-south-1", "display_name": "Bank A"},
                {"tenant_id": "hospital-b", "region": "eu-west-1", "display_name": "Hospital B"},
            ]
        )

        async def beat(age_sec: float, hb_id: str):
            hb = CollectorHeartbeat(
                heartbeat_id=hb_id,
                tenant_id="bank-a",
                region="ap-south-1",
                collector_id="col-blr-01",
                sent_time_utc=_iso_minus(age_sec),
                total_sent_count=5,
            )
            await db.upsert_collector_heartbeat(
                "ap-south-1", hb, health_state="Excellent", heartbeat_time_utc=_iso_minus(age_sec)
            )

        async def seed_source(source_id: str, age_sec: float):
            await db.upsert_source_state(
                "ap-south-1",
                tenant_id="bank-a",
                source_id=source_id,
                collector_id="col-blr-01",
                source_type="server",
                upstream_source_id=None,
                health_state="Good",
                latest_event_time_utc=_iso_minus(age_sec),
                last_ingested_utc=_iso_minus(age_sec),
                latest_metrics_json=_metrics().model_dump_json(),
                latest_security_json="{}",
                secrets_scrubbed_delta=0,
            )

        async def cfg_provider(_tenant_id: str) -> ThresholdConfig:
            return ThresholdConfig()

        await beat(5, "hb-wd-1")
        await seed_source("src-a", 40)
        await seed_source("src-b", 60)

        watchdog = Watchdog(db, cfg_provider, interval_sec=5.0)
        await watchdog.run_watchdog_pass()

        src_a = await db.get_source_state("ap-south-1", "bank-a", "src-a")
        src_b = await db.get_source_state("ap-south-1", "bank-a", "src-b")
        assert src_a["health_state"] == "Fair"
        assert src_b["health_state"] == "Poor"
        collector = await db.get_collector("ap-south-1", "col-blr-01")
        assert collector["health_state"] == "Excellent"
        transitions = await db.list_transitions("ap-south-1", "bank-a", limit=20)
        stale_reasons = [t["reason"] for t in transitions if "freshness window" in t["reason"]]
        assert len(stale_reasons) == 2
        after_pass1 = len(transitions)

        await beat(52, "hb-wd-2")
        await watchdog.run_watchdog_pass()

        collector = await db.get_collector("ap-south-1", "col-blr-01")
        assert collector["health_state"] == "Poor"
        assert collector["offline_detected_utc"] is not None
        detection = (
            parse_utc_iso(collector["offline_detected_utc"]) - parse_utc_iso(_iso_minus(52))
        ).total_seconds()
        assert 50 <= detection <= 60

        src_a = await db.get_source_state("ap-south-1", "bank-a", "src-a")
        src_b = await db.get_source_state("ap-south-1", "bank-a", "src-b")
        assert src_a["health_state"] == "Poor"
        assert src_b["health_state"] == "Poor"

        transitions = await db.list_transitions("ap-south-1", "bank-a", limit=40)
        reasons = [t["reason"] for t in transitions]
        assert "Collector heartbeat timeout" in reasons
        assert "Stale data: collector unreachable" in reasons
        after_pass2 = len(transitions)
        assert after_pass2 > after_pass1

        await watchdog.run_watchdog_pass()
        transitions = await db.list_transitions("ap-south-1", "bank-a", limit=40)
        assert len(transitions) == after_pass2

        await db.close()

    asyncio.run(scenario())
