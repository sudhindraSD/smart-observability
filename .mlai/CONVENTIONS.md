# Conventions

## Frozen contracts (Slice 1)
- `shared/contracts.py` is the cross-tier contract: every class name, enum value and field name is frozen because Slices 2-4 import them directly. Never rename; only additive changes allowed.
- `EgressMetadataPayload.egress_sent_utc` and `is_backlog_replay` are stamped ONLY in `sender.py` (Slice 2); the scrubber leaves them `None`.
- `InternalRawEvent` never leaves Box 1 (collector); only `EgressMetadataPayload` crosses to Tier 2.

## No ML dependencies
- ZERO `river` / HalfSpaceTrees / ML libraries anywhere (HST failed separation on 6-D telemetry and erased zero-variance counters). `saas/detector.py` is pure stdlib (median/MAD z-scores).
- `IncidentExplanation` must not gain an `hst_anomaly_score` field.

## Privacy invariants
- `raw_log_line`, real hostnames and private IPs never appear in egress payloads or `alert_context`; `alert_context` is a fixed template.
- FastAPI 422s must use `shared/safe_errors.install_safe_validation_handler` — the default handler echoes rejected input values (verified: it leaks even with `hide_input_in_errors=True`).

## Run / test
- Use `.venv/Scripts/python` (venv not on PATH): `.venv/Scripts/python -m pytest -s -v`; `.venv/Scripts/python scripts/gen_certs.py [--lan-ip X]`.

## Slice 3 (Box 2 central SaaS)
- `saas/` uses pure `aiosqlite` with three separate WAL DBs under `SAAS_DATA_DIR` (default `data/`): `saas_control_plane.db` (tenants, threshold_config), `saas_ap_south_1.db`, `saas_eu_west_1.db`. Physical regional residency: a tenant's rows never cross regional DB files.
- Auth: collectors authenticate with seeded `X-Collector-Token` values (`tok-bank-a-blr`, `tok-hosp-b-fra`); tenant users get HS256 JWTs (`SAAS_JWT_SECRET`, demo password `demo123` via `SAAS_DEMO_PASSWORD`). `tenant_id`/`region` always come from the verified token, never from query parameters.
- Ingest is idempotent on `payload_id` (`INSERT OR IGNORE`); duplicates bump `duplicates_blocked_count` and skip AIOps. Time-series queries order by `event_time_utc ASC`; the out-of-order guard skips only live-state updates, never history storage.
- Backlog replays (`is_backlog_replay=True`) are stored and counted but never create/merge incidents and are excluded from SLA latency stats (Amendment A6).
- The 2-level correlator merges OPEN incidents within a 45-second WALL-CLOCK window on `alert_created_utc` (event times are irrelevant to merging); Level 1 matches topology via `upstream_source_id`, Level 2 falls back to same `(tenant_id, collector_id)`.
- Watchdog: `run_watchdog_pass(now_utc=None)` is directly callable for deterministic tests; collector offline at 50s ("Collector heartbeat timeout"), source stale at 35s -> "Fair" and 55s -> "Poor" ("Stale data: ..." reasons); only-downgrade semantics make repeat passes idempotent.
- `saas.aiops.incident_row_to_record(row, region)` takes the region explicitly — the frozen `incidents` table has no region column.

## Slice 4 (dashboard live-mode chaos drills)
- `dashboard/src/chaos.js` live drills must not require `network_device` telemetry: when only the server has egressed, `cascade_incident`/`latency_spike` derive the router identity from the server's frozen `upstream_device_real_name` field (`real_ip` stays absent — it is optional on `InternalRawEvent`).
- Cascade downstream events are stamped with `event_time_utc` at their post time, so all consecutive posts (router→down1→down2) are ~1.5s apart in both wall clock and event time, not just the last pair.
