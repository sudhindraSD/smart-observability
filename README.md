# SentinelOps — Secure Multi-Tenant AIOps Observability Platform

A two-tier, privacy-first observability demo: telemetry is scrubbed **inside the customer
network** (Box 1 collectors) before a single byte leaves it, correlated into explainable
incidents by a pure-stdlib statistical engine (Box 2 central SaaS), and watched live on a
React console. Secrets, hostnames and private IPs **never cross the wire** — and the test
suite proves it.

Everything in this README was executed and verified on **2026-11-21** on this machine
(Windows 11, win32 x64, Python 3.13.7, Node v22.15.0). The exact commands and their real
results are in [Verification log](#verification-log-all-numbers-from-a-fresh-run).

| Check | Command | Result (fresh run) |
|---|---|---|
| Backend suite | `.venv/Scripts/python -m pytest -s -v` | **42 passed** in 7.52s, 0 failed |
| Dashboard unit tests | `node --test src/chaos.test.js src/api.test.js src/timefmt.test.js` | **39 pass, 0 fail**, 0 skipped (6.52s) |
| Production build | `npm run build` | **built in 1.81s**, 0 errors |

---

## Table of contents

1. [Why this exists](#why-this-exists)
2. [Architecture](#architecture)
3. [Quickstart — one command](#quickstart--one-command)
4. [First success in five minutes](#first-success-in-five-minutes)
5. [Manual startup (all five services, verbatim)](#manual-startup-all-five-services-verbatim)
6. [Ports and services](#ports-and-services)
7. [Configuration reference](#configuration-reference)
8. [HTTP and WebSocket API reference](#http-and-websocket-api-reference)
9. [Chaos drills](#chaos-drills)
10. [How detection works (exact numbers)](#how-detection-works-exact-numbers)
11. [Incident correlator](#incident-correlator)
12. [Watchdog](#watchdog)
13. [Remediation](#remediation)
14. [Privacy and security guarantees](#privacy-and-security-guarantees)
15. [Multi-tenancy and data residency](#multi-tenancy-and-data-residency)
16. [Dashboard tour](#dashboard-tour)
17. [Data files on disk](#data-files-on-disk)
18. [Testing — every case, every number](#testing--every-case-every-number)
19. [Verification log (all numbers from a fresh run)](#verification-log-all-numbers-from-a-fresh-run)
20. [Troubleshooting](#troubleshooting)
21. [Repository layout](#repository-layout)
22. [Known limitations](#known-limitations)

---

## Why this exists

Classic AIOps platforms ship raw logs to the cloud and promise to be careful. This project
flips the order of operations:

- **Box 1 (collector) runs inside the customer network.** It ingests raw telemetry, scans
  every log line for secrets, pseudonymises hostnames, drops private IPs, and only then
  produces the compact `EgressMetadataPayload` that is allowed to leave. The raw event
  type (`InternalRawEvent`) is structurally incapable of leaving Box 1 — only the scrubbed
  payload type exists on the egress path.
- **Box 2 (central SaaS) never sees a secret.** It stores scrubbed payloads in physically
  separate regional SQLite databases, correlates anomalies into incidents with a
  deterministic, explainable detector (median/MAD z-scores — zero ML dependencies), and
  proposes only reversible *simulation* remediations that a human must approve.
- **Every claim is tested.** 42 backend tests + 39 dashboard tests assert the privacy
  invariants, the detector math, the correlation window, dedup/out-of-order behaviour,
  multi-tenant isolation and the watchdog timers.

The demo tenants are fictional: **bank-a** (a bank in Bengaluru, India) and
**hospital-b** (a hospital in Frankfurt, Germany).

---

## Architecture

```text
                        CUSTOMER NETWORKS (Box 1 boundary)
 ┌───────────────────────────────┐   ┌───────────────────────────────┐
 │  Bank A (India, ap-south-1)   │   │  Hospital B (EU, eu-west-1)   │
 │                               │   │                               │
 │  live host log  data/         │   │  Mock Chaos Stream  :9000     │
 │  live_host.log  ──► Collector A│  │  ws://…/ws/stream/hospital-b  │
 │  :4001  STREAM_MODE=live      │   │        │                      │
 │  scrub → outbox (SQLite WAL)  │   │        ▼                      │
 │        │  batch ≤25, 0.25s    │   │  Collector B :4002            │
 │        ▼                      │   │  STREAM_MODE=ws               │
 └────────┼──────────────────────┘   │  scrub → outbox (SQLite WAL)  │
          │  HTTPS (self-signed)     └────────┼──────────────────────┘
          │  POST /api/v1/ingest/{region}      │  same egress path
          ▼                                    ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  BOX 2 — Central SaaS  https://localhost:8000  (TLS only)       │
 │  • token-auth collectors, JWT tenant users                      │
 │  • 3 physically separate SQLite WAL DBs (control + 2 regions)   │
 │  • detector (median/MAD z) → correlator (45 s window)           │
 │  • watchdog (offline/stale) → remediation (approval-gated)      │
 └───────────────┬─────────────────────────────────────────────────┘
                 │  Vite dev proxies: /api /ws → :8000, /chaos → :9000,
                 │                   /col-a → :4001, /col-b → :4002
                 ▼
 ┌─────────────────────────────────────────────────────────────────┐
 │  React SaaS Dashboard  http://localhost:3000                    │
 │  fleet health · sources · incidents · SLA strip · chaos drawer  │
 └─────────────────────────────────────────────────────────────────┘
```

| Component | Code | Port | Role |
|---|---|---|---|
| Mock Chaos Stream (Box 0) | `mock_stream/stream_server.py` | 9000 | Simulates both customer sites at 1 event/sec per source; serves chaos scenarios |
| Collector A (Box 1) | `collector/main.py` | 4001 | bank-a / ap-south-1 / `STREAM_MODE=live` (tails `data/live_host.log`) |
| Collector B (Box 1) | `collector/main.py` | 4002 | hospital-b / eu-west-1 / `STREAM_MODE=ws` (consumes the mock stream over WebSocket) |
| Central SaaS (Box 2) | `saas/main.py` | 8000 (HTTPS) | Multi-tenant ingest, incidents, remediation, watchdog, SLA |
| React Dashboard (Box 2 UI) | `dashboard/` | 3000 | Live console over the SaaS API |

Frozen contracts live in `shared/contracts.py` — every class name, enum value and field
name there is imported directly by Slices 2–4 and must never be renamed (additive changes
only).

---

## Quickstart — one command

Prerequisites (one-time — the exact versions this venv runs):

```powershell
cd smart-observability
python -m venv .venv
.venv\Scripts\pip install fastapi==0.165.0 uvicorn==0.54.0 aiosqlite==0.22.1 httpx==0.28.1 psutil==7.2.2 pydantic==2.14.4 PyJWT==2.15.1 pytest==9.2.0 websockets==17.4
cd dashboard ; npm install ; cd ..
```

(There is no `requirements.txt` in this repo — the pins above are read straight from the
working `.venv` via `pip freeze`.)

Then, every run:

```powershell
.\run_demo.ps1
```

The launcher (`run_demo.ps1`) does, in order:

1. Verifies `.venv\Scripts\python.exe` exists (exits with instructions if not).
2. Generates `certs/cert.pem` + `certs/key.pem` via `scripts/gen_certs.py` if missing.
3. Creates `data/` and `data/live_host.log` if missing.
4. **Kills zombie listeners** on ports 9000, 8000, 4001, 4002, 3000 (this is what cures
   the classic `ssl3_get_record:wrong version number` and silent-port-bump failures).
5. Opens five titled PowerShell windows, spaced so they start in order:

| Window | Title | Service |
|---|---|---|
| 1 | `1 - Mock Chaos Stream (:9000)` | `uvicorn mock_stream.stream_server:app --port 9000` |
| 2 | `2 - Box 2 Central SaaS HTTPS (:8000)` | `uvicorn saas.main:app --port 8000 --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem` |
| 3 | `3 - Box 1 Collector A - Bank A / India / LIVE (:4001)` | `uvicorn collector.main:app --port 4001` + 12 env vars |
| 4 | `4 - Box 1 Collector B - Hospital B / EU / WS (:4002)` | `uvicorn collector.main:app --port 4002` + 12 env vars |
| 5 | `5 - Box 2 React SaaS Dashboard (:3000)` | `node node_modules\vite\bin\vite.js --port 3000 --strictPort` |

6. Prints the clickable URLs and the judge-secret one-liner.

**To stop:** close the five windows. The next `.\run_demo.ps1` clears any leftovers.

---

## First success in five minutes

1. Run `.\run_demo.ps1`, wait ~15 seconds.
2. Open **http://localhost:3000** — the dashboard. Do not open :8000 or :9000 directly;
   the dashboard proxies them for you.
3. Within seconds the **fleet strip** shows both collectors online and sources flowing.
4. Click a source to see its live time-series (ordered by `event_time_utc ASC`).
5. Open the **chaos drawer** and fire `Latency Spike` — within ~30 s an incident appears
   with an explainable signal list (metric, z-score, contribution).
6. Fire `Cascade Incident` — one merged incident covering router + 2 downstream servers.
7. Approve the remediation plan from the incident panel, then roll it back — the audit
   trail records every transition.

Judge-secret demo (paste in any PowerShell window — pushes a fake secret through Bank A's
live pipeline; it is scrubbed locally and a security incident is raised **without** the
raw line ever leaving the machine):

```powershell
Add-Content -Path 'data\live_host.log' -Value 'payment callback trace: Authorization: Bearer sk_live_98a7sd98a7sd password=hunter2xyz client_ip=10.20.4.15 result=declined'
```

---

## Manual startup (all five services, verbatim)

If you prefer separate terminals (or you are on macOS/Linux and want the services without
the PowerShell launcher), these are the exact commands the launcher runs — copy them as-is:

```powershell
# 1. Mock Chaos Stream
.venv\Scripts\python -m uvicorn mock_stream.stream_server:app --host 0.0.0.0 --port 9000

# 2. Central SaaS — MUST be HTTPS on :8000 (the dashboard proxy expects TLS)
.venv\Scripts\python -m uvicorn saas.main:app --host 0.0.0.0 --port 8000 `
    --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem

# 3. Collector A (Bank A, live mode)
$env:TENANT_ID='bank-a';        $env:REGION='ap-south-1'
$env:COLLECTOR_ID='col-blr-01'; $env:COLLECTOR_TOKEN='tok-bank-a-blr'
$env:COLLECTOR_PORT='4001';     $env:COLLECTOR_DB_PATH='data/collector_bank_a.db'
$env:STREAM_MODE='live';        $env:LIVE_LOG_FILE='data/live_host.log'
$env:SAAS_BASE_URL='https://localhost:8000'; $env:SAAS_TLS_VERIFY='false'
$env:LOCAL_HMAC_SALT='bank-a-local-only-salt'
.venv\Scripts\python -m uvicorn collector.main:app --host 0.0.0.0 --port 4001

# 4. Collector B (Hospital B, WebSocket mode)
$env:TENANT_ID='hospital-b';     $env:REGION='eu-west-1'
$env:COLLECTOR_ID='col-fra-01';  $env:COLLECTOR_TOKEN='tok-hosp-b-fra'
$env:COLLECTOR_PORT='4002';      $env:COLLECTOR_DB_PATH='data/collector_hosp_b.db'
$env:STREAM_MODE='ws';           $env:STREAM_URL='ws://localhost:9000/ws/stream/hospital-b'
$env:SAAS_BASE_URL='https://localhost:8000'; $env:SAAS_TLS_VERIFY='false'
$env:LOCAL_HMAC_SALT='hospital-b-local-only-salt'
.venv\Scripts\python -m uvicorn collector.main:app --host 0.0.0.0 --port 4002

# 5. Dashboard (start Vite directly — see Troubleshooting for why not `npm run dev --`)
cd dashboard
node node_modules\vite\bin\vite.js --port 3000 --strictPort
```

Certificates can be regenerated any time (add `--lan-ip X` to serve from another machine):

```powershell
.venv\Scripts\python scripts\gen_certs.py
```

---

## Ports and services

| Port | Service | Scheme | Notes |
|---|---|---|---|
| 3000 | React dashboard (Vite dev) | HTTP | `--strictPort`: fails loudly if taken, never silently bumps |
| 4001 | Collector A | HTTP | Local-only surface (status, egress proof, raw ingest) |
| 4002 | Collector B | HTTP | Same surface, hospital-b identity |
| 8000 | Central SaaS | **HTTPS/TLS** | Self-signed cert; browsers/proxies use `secure:false` |
| 9000 | Mock Chaos Stream | HTTP | Also the chaos-scenario trigger endpoint |

---

## Configuration reference

### Collector (`collector/main.py` — `create_app()` reads env with clean defaults)

| Env var | Example | Meaning |
|---|---|---|
| `TENANT_ID` | `bank-a` | Tenant identity stamped on egress |
| `REGION` | `ap-south-1` | Regional routing key at the SaaS |
| `COLLECTOR_ID` | `col-blr-01` | Collector identity (correlator Level 2 key) |
| `COLLECTOR_TOKEN` | `tok-bank-a-blr` | Seeded `X-Collector-Token` for Box 2 auth |
| `COLLECTOR_PORT` | `4001` | Local listen port |
| `COLLECTOR_DB_PATH` | `data/collector_bank_a.db` | Local outbox (SQLite WAL) |
| `STREAM_MODE` | `live` \| `ws` | Tail a log file, or consume a WebSocket stream |
| `STREAM_URL` | `ws://localhost:9000/ws/stream/hospital-b` | WS source (mode `ws`) |
| `LIVE_LOG_FILE` | `data/live_host.log` | Log source (mode `live`) |
| `SAAS_BASE_URL` | `https://localhost:8000` | Egress target |
| `SAAS_TLS_VERIFY` | `false` | Trust the self-signed demo cert (`sender.py` honours the same path/cert) |
| `LOCAL_HMAC_SALT` | `bank-a-local-only-salt` | Salt for deterministic pseudonymisation — stays local |

### Central SaaS (`saas/main.py`)

| Env var | Default | Meaning |
|---|---|---|
| `SAAS_DATA_DIR` | `data/` | Root for the three SQLite WAL databases |
| `SAAS_JWT_SECRET` | demo value | HS256 signing secret for tenant-user JWTs |
| `SAAS_DEMO_PASSWORD` | `demo123` | Password for the seeded demo users `bank-a` / `hospital-b` |

### Mock stream

No configuration — both sites (`bank-a`, `hospital-b`) and their sources are defined in
`mock_stream/stream_server.py` (`SITES`).

---

## HTTP and WebSocket API reference

### Collector local API (each collector, :4001 / :4002)

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Landing page (egress-proof panel UI) |
| GET | `/api/status` | Link state, queue depth, counters |
| GET | `/api/egress-proof?limit=N` | The exact payloads that left the box (audit) |
| GET | `/api/sent-ids` | Payload IDs already acked by Box 2 |
| POST | `/control/toggle-link` | Cut/restore the uplink (demo of buffering) |
| POST | `/api/ingest-raw` | Push a raw `InternalRawEvent` into the local pipeline |

### Central SaaS (:8000, HTTPS, all under JWT or collector-token auth)

| Method | Path | Purpose |
|---|---|---|
| GET | `/healthz` | Liveness |
| POST | `/api/v1/auth/login` | `LoginRequest` → tenant JWT (HS256) |
| POST | `/api/v1/ingest/{region}` | Collector batch ingest; idempotent on `payload_id` |
| POST | `/api/v1/heartbeat/{region}` | Collector heartbeat (drives watchdog) |
| GET | `/api/v1/overview` | Fleet + sources snapshot for the dashboard |
| GET | `/api/v1/sources/{source_id}/series` | Time series, ordered `event_time_utc ASC` |
| GET | `/api/v1/incidents` | Incident list with explanations + remediation plans |
| POST | `/api/v1/incidents/{incident_id}/approve` | Approve the proposed (simulation) plan |
| POST | `/api/v1/incidents/{incident_id}/rollback` | Roll back an approved action |
| GET | `/api/v1/transitions` | Health/state transition log |
| GET / PUT | `/api/v1/thresholds` | Read/update per-tenant detector thresholds |
| GET | `/api/v1/sla-metrics` | Ingest→incident latency stats (backlog replays excluded) |
| WS | `/ws/{tenant_id}` | Live incident/stream pushes for the dashboard |

`tenant_id` and `region` always come from the **verified token**, never from query
parameters. Validation failures return 422 through
`shared/safe_errors.install_safe_validation_handler`, which strips rejected input values
(the default FastAPI handler echoes them back — a verified leak).

### Mock stream (:9000)

| Method | Path | Purpose |
|---|---|---|
| WS | `/ws/stream/{site}` | Live `InternalRawEvent` JSON frames (1/sec per source) |
| GET | `/api/poll/{site}` | HTTP poll alternative |
| POST | `/chaos/{scenario}` | Trigger a chaos scenario (see below) |

---

## Chaos drills

Seven buttons in the dashboard's chaos drawer. Six are executed by the mock stream
(`POST /chaos/{scenario}`); `out_of_order` is synthesised browser-side by
`dashboard/src/chaos.js` (it needs no server cooperation).

| Scenario | What it does | Expected outcome |
|---|---|---|
| `secret` | Injects a log line containing an API key, password, hex key and private IP | Secret scrubbed locally; security incident raised from counts only; raw line never egresses |
| `failed_logins` | Posts **exactly 14** failed-login events on one source | Security incident without any raw logs |
| `latency_spike` | Latency jumps far beyond the robust baseline | Explainable anomaly incident (z-scores listed) |
| `cpu_anomaly` | CPU/memory spike | Robust z-score incident; recovers after baseline re-learns |
| `cascade_incident` | Router + 2 downstream servers degrade, posts spaced **1.5 s** apart | **One merged incident** via the 45 s correlator window |
| `duplicate_payload` | Replays an already-sent `payload_id` | Stored once; `duplicates_blocked_count` bumps; no second incident |
| `out_of_order` | Sends an older event after a newer one | History stored; live-state update skipped (guard) |

---

## How detection works (exact numbers)

`saas/detector.py` is pure Python stdlib — **zero ML dependencies** (no `river`, no
Half-Space Trees; an earlier HST attempt failed separation on 6-D telemetry and erased
zero-variance counters, so it was removed and a regression test now guards that).

| Constant | Value | Meaning |
|---|---|---|
| `WINDOW_SIZE` | 60 | Rolling baseline window (samples) per source |
| `WARMUP_MIN` | 15 | Samples learned before statistics may flag (security triggers exempt) |
| `ESCAPE_AFTER` | 30 | Consecutive flags before the 1-in-3 escape hatch re-admits samples |
| `SINGLE_Z` | 4.0 | Single-metric trigger threshold |
| `ELEVATED_Z` | 1.7 | "Elevated" threshold feeding the joint score |
| `JOINT_Z` | 3.2 | Joint L2 z-score trigger threshold |
| `MIN_MAD` | cpu 2.0 · mem 1.5 · disk 1.0 · latency 3.0 · loss 0.2 · bw 15.0 · logins 1.0 | Median-absolute-deviation floors (stops zero-variance counters flagging) |
| `TWO_SIDED_METRICS` | `bandwidth_mbps` | Only bandwidth flags in both directions |

Mechanics:

- Baselines are **median/MAD** (robust to outliers), per metric, per source.
- During warm-up the baseline learns; security triggers (`risk ∈ {high, critical}`) bypass
  the statistical gate — warm-up gates statistics, never security.
- **Poisoning guard:** flagged samples are never admitted into the baseline, so an attack
  cannot redefine "normal". The escape hatch prevents permanent lock-out.
- Signal weights are computed per incident and **sum to exactly 100** (tested).
- Confidence is a bounded, monotonic percentage (tested).

---

## Incident correlator

`saas/aiops.py` merges alerts so a cascade produces **one** incident, not dozens:

- Merging window: `CORRELATION_WINDOW_SEC = 45.0` seconds of **wall-clock time** on
  `alert_created_utc` (event times are deliberately irrelevant to merging).
- Level 1: topology match via `upstream_source_id`.
- Level 2 fallback: same `(tenant_id, collector_id)`.
- Incidents carry an `IncidentExplanation`: contributing signals with metric names,
  z-scores and contributions — every alert is explainable, never a black-box score.
- `incident_row_to_record(row, region)` takes the region explicitly because the frozen
  `incidents` table has no region column.

---

## Watchdog

`saas/watchdog.py` runs a pass **every 5 seconds** against every regional DB.
`run_watchdog_pass(now_utc=None)` is directly callable with an injected clock, which is
exactly how the tests pin the timings:

| Condition | Threshold | Effect |
|---|---|---|
| Collector offline | no heartbeat for **50 s** | "Collector heartbeat timeout" |
| Source stale | no data for **35 s** | Health downgraded to **Fair** — "Stale data: …" |
| Source very stale | no data for **55 s** | Health downgraded to **Poor** — "Stale data: …" |

Downgrades are **only-downgrade**: repeated passes are idempotent and never silently
promote health back.

---

## Remediation

`saas/remediation.py` is safe by construction:

- The policy gate only ever passes **reversible simulation actions** — e.g.
  `SIMULATE_FAILOVER_UPLINK`. Destructive operations are blocked at the gate, not at
  runtime.
- Lifecycle: plan proposed → human **approves** → executed (simulated) → optionally
  **rolled back**. Every transition lands in `RemediationAuditEntry` records.
- Every incident carries a `RemediationPlan` from birth; there is no path that mutates
  production systems.

---

## Privacy and security guarantees

Each guarantee has at least one test behind it (see [Testing](#testing--every-case-every-number)).

1. **Raw logs never leave Box 1.** `InternalRawEvent` exists only inside the collector;
   only `EgressMetadataPayload` crosses to Tier 2.
2. **Secret scrubbing** (`collector/scrubber.py`) detects and redacts:
   `api_key` (including `Bearer …` tokens), `credential` (`password=…` etc.),
   `hex_key` (≥32 hex chars), `bare_token` (random-looking Base62 runs), emails and
   **private IPs**. The audit records *which types* were seen — counts, never contents.
3. **Pseudonymisation** of hostnames is deterministic per salt (`LOCAL_HMAC_SALT`),
   prefixed, and the same upstream maps to the same pseudonym (tested).
4. **`alert_context` is a fixed template** — it can never interpolate raw credentials.
5. **FastAPI 422s are leak-proof:** the default handler echoes rejected input (verified to
   leak even with `hide_input_in_errors=True`), so both apps install
   `install_safe_validation_handler`, which strips input from the error (tested both ways).
6. **Egress metadata is stamped in exactly one place:** `sender.py` alone writes
   `egress_sent_utc` and `is_backlog_replay`; the scrubber leaves them `None` (tested).
7. **Backlog replays never alert:** payloads older than `_BACKLOG_REPLAY_THRESHOLD_SEC = 5.0`
   are marked `is_backlog_replay`, stored and counted but never create or merge incidents
   and are excluded from SLA latency stats.
8. **Idempotent ingest:** `INSERT OR IGNORE` on `payload_id`; duplicates bump
   `duplicates_blocked_count` and skip AIOps.
9. **Out-of-order guard:** late events are stored in history but never overwrite live state.
10. **Physical data residency:** a tenant's rows live in exactly one regional DB file and
    never cross (tested with two tenants).

---

## Multi-tenancy and data residency

| Tenant | Region | Collector | Token | Regional DB |
|---|---|---|---|---|
| `bank-a` | `ap-south-1` | `col-blr-01` | `tok-bank-a-blr` | `data/saas_ap_south_1.db` |
| `hospital-b` | `eu-west-1` | `col-fra-01` | `tok-hosp-b-fra` | `data/saas_eu_west_1.db` |

Plus the control plane: `data/saas_control_plane.db` (tenants, threshold config).

- Collectors authenticate with the seeded static tokens above (`X-Collector-Token`).
- Tenant users authenticate with HS256 JWTs from `POST /api/v1/auth/login`; demo users are
  `bank-a` and `hospital-b`, password `demo123` (`SAAS_DEMO_PASSWORD`).
- Unknown region → 404 `unknown region: …`. Cross-region reads are impossible by
  construction: each region is a separate database file, and `saas_eu_west_1.db` /
  `saas_ap_south_1.db` never share rows.

Simulated sites and sources (mock stream):

| Site | Timezone | Sources |
|---|---|---|
| bank-a | Asia/Kolkata | `core-rtr-blr-01` (network device), `pay-db-01.internal` (server) |
| hospital-b | Europe/Berlin | `edge-rtr-fra-01` (network device), `ehr-app-01.internal` (server) |

---

## Dashboard tour

`dashboard/` is a Vite + React 19 + Tailwind v4 + Recharts + lucide-react app
(Tailwind v4 is wired through `@tailwindcss/vite` — there is deliberately **no**
`tailwind.config.js` / `postcss.config.js`).

| Module | Role |
|---|---|
| `src/App.jsx` | Layout + data loop |
| `src/api.js` | Typed fetchers for every SaaS/collector endpoint |
| `src/chaos.js` | Chaos drill firing, incl. browser-side `out_of_order` and router-identity derivation from `upstream_device_real_name` when no network telemetry exists yet |
| `src/constants.js` | Frozen tenant catalogue mirroring `shared/contracts.py` verbatim |
| `src/timefmt.js` | Timezone-aware formatting (Asia/Kolkata vs Europe/Berlin), pct95 |
| `src/components/TopBar.jsx` | Tenant switcher, login state |
| `src/components/SlaStrip.jsx` | Ingest→incident SLA numbers |
| `src/components/CollectorFleet.jsx` | Both collectors' health/heartbeat |
| `src/components/SourcesPanel.jsx` | Per-source live series |
| `src/components/IncidentsPanel.jsx` | Incidents + explanations + approve/rollback |
| `src/components/TransitionsTable.jsx` | Health transition log |
| `src/components/ThresholdsModal.jsx` | Per-tenant threshold editing |
| `src/components/ChaosDrawer.jsx` | The seven drill buttons |

Dev proxies (`dashboard/vite.config.js`):

| Prefix | Target | Notes |
|---|---|---|
| `/api`, `/ws` | `https://localhost:8000` | `ws: true`, `secure: false` (self-signed cert) |
| `/chaos` | `http://localhost:9000` | Chaos triggers |
| `/col-a` → `/` | `http://localhost:4001` | Prefix rewritten away |
| `/col-b` → `/` | `http://localhost:4002` | Prefix rewritten away |

---

## Data files on disk

| File | Owner | Contents |
|---|---|---|
| `data/collector_bank_a.db` (+ `-wal`, `-shm`) | Collector A | Raw events, scrubbed outbox, egress audit |
| `data/collector_hosp_b.db` (+ `-wal`, `-shm`) | Collector B | Same, hospital-b |
| `data/saas_control_plane.db` | SaaS | Tenants, threshold config |
| `data/saas_ap_south_1.db` (+ `-wal`, `-shm`) | SaaS | bank-a scrubbed payloads, incidents, transitions |
| `data/saas_eu_west_1.db` (+ `-wal`, `-shm`) | SaaS | hospital-b equivalents |
| `data/live_host.log` | Collector A source | Live log tail (judge-secret demo target) |

All SQLite databases run in WAL mode. Deleting a DB file resets that tier's history; the
launcher recreates missing directories but never deletes data.

---

## Testing — every case, every number

Fresh run **2026-11-21**. Backend: **42 passed, 0 failed, 0 skipped in 7.52s**
(win32, Python 3.13.7, pytest 9.2.0, pluggy 1.7.0, anyio 4.16.0).
36 test functions, some parametrised → 42 collected tests.

### `tests/test_aiops_separation.py` — detector correctness (5 tests)

| Test | What it proves |
|---|---|
| `test_statistical_separation_across_seeds` | Normal traffic and attacks separate statistically across random seeds |
| `test_warmup_gates_statistics_but_not_security` | Warm-up (<15 samples) blocks statistical flags but security triggers still fire |
| `test_poisoning_guard_keeps_baseline_clean` | Flagged samples never enter the baseline |
| `test_compute_signal_weights_sum_to_exactly_100` | Signal weights sum to exactly 100 |
| `test_compute_confidence_pct_bounds_and_monotonic` | Confidence stays in bounds and is monotonic |

### `tests/test_scrubber.py` — privacy engine (13 functions → 19 collected)

| Test | What it proves |
|---|---|
| `test_known_secret_samples_are_detected` (×5: `sk_live_abc123`→api_key, 2 bare tokens→bare_token, HEX32→hex_key, `password=abc123`→credential) | Every secret class is caught |
| `test_negative_controls_not_flagged` (×2: `AuthenticationService`, `status=200 latency=12ms`) | Benign strings produce zero false positives |
| `test_looks_random_thresholds` | Randomness scoring thresholds behave as specified |
| `test_scan_none_and_empty` | Degenerate inputs are safe |
| `test_scrub_to_egress_drops_all_sensitive_fields` | The egress payload drops every sensitive field |
| `test_forced_payload_id_preserved_and_sender_fields_unset` | `payload_id` survives; `egress_sent_utc`/`is_backlog_replay` stay `None` (scrubber never stamps sender fields) |
| `test_pseudonymize_deterministic_and_prefixed` | Same input+salt → same pseudonym, correctly prefixed |
| `test_upstream_pseudonymized_with_same_salt` | Upstream host maps consistently |
| `test_alert_context_never_leaks_raw_credentials` | Fixed-template context cannot leak secrets |
| `test_security_window_counts_and_escalates` | Auth-failure counting escalates to a security trigger |
| `test_default_fastapi_422_echoes_rejected_secret` | Documents the leak: default FastAPI 422 echoes the secret |
| `test_safe_validation_handler_strips_input` | The installed handler strips it |
| `test_bare_base62_recall` (×2: length 12 → ≥0.85, length 20 → ≥0.88) | Bare-token recall floors |

### `tests/test_slice2_collector.py` — Box 1 pipeline (8 tests)

| Test | What it proves |
|---|---|
| `test_a_secrets_stay_local_egress_is_clean` | End-to-end: secret in → clean egress out |
| `test_b_link_cut_buffers_ten_events` | Uplink cut → 10 events buffered locally |
| `test_c_restore_drains_ten_with_backlog_and_heartbeat` | Restore → all 10 drain as backlog replays + heartbeat resumes |
| `test_d_prune_expired_raw_keeps_live_rows` | Raw retention pruning keeps live rows |
| `test_e_chaos_scenarios_return_200_with_valid_events` | All mock-stream chaos scenarios yield valid events |
| `test_e_ws_stream_hospital_b_delivers_valid_json_frames` | Regression for the Bug-1 crash: `dict` frames are sent via `send_json`, no `AttributeError` |
| `test_f_live_adapter_collects_real_telemetry` | Live adapter produces real telemetry |
| `test_f_normalize_external_event_maps_aliases` | External event aliases normalise correctly |

### `tests/test_slice3_e2e.py` — Box 2 end-to-end (10 tests)

| Test | What it proves |
|---|---|
| `test_01_secret_scrub_and_422_leak_guard` | Secret scrubbed + 422 leak guard holds |
| `test_02_backlog_replay_never_alerts` | Backlog replays store/count but never alert |
| `test_03_failed_logins_raise_security_incident_without_raw_logs` | 14 failed logins → security incident, zero raw logs |
| `test_04_latency_spike_explainable_anomaly` | Latency spike → explainable incident |
| `test_05_cpu_memory_spike_robust_zscore` | CPU/mem spike detected by robust z-scores |
| `test_06_cascade_correlation_single_incident` | Cascade merges into exactly one incident |
| `test_07_dedup_and_out_of_order` | Duplicate `payload_id` blocked; out-of-order history kept, live state guarded |
| `test_08_remediation_lifecycle` | Propose → approve → rollback, destructive actions blocked |
| `test_09_multi_tenant_isolation` | Tenants cannot see each other; rows never cross regional DBs |
| `test_10_watchdog_offline_and_stale_detection` | 50 s offline, 35 s Fair, 55 s Poor, idempotent repeat passes |

### Dashboard unit tests — 39 (node:test, 0 fail)

| File | Count | Covers |
|---|---|---|
| `dashboard/src/chaos.test.js` | 20 | Scenario firing, router identity from `upstream_device_real_name`, 1.5 s cascade spacing, `out_of_order` synthesis |
| `dashboard/src/api.test.js` | 11 | Endpoint URLs, request/response shapes, auth headers |
| `dashboard/src/timefmt.test.js` | 8 | Timezone-aware formatting, `pct95` of a rolling window, ISO timestamp emission |

### Production build

`npm run build` → `✓ built in 1.81s`, 0 errors:

```text
dist/index.html                   0.48 kB │ gzip:   0.32 kB
dist/assets/index-lX9lMvpB.css   31.58 kB │ gzip:   6.48 kB
dist/assets/index-DpnOy7mf.js   690.85 kB │ gzip: 202.63 kB
```

(The 690 kB JS chunk triggers only Vite's standard chunk-size advisory — not an error.)

---

## Verification log (all numbers from a fresh run)

Executed 2026-11-21 on this machine. Output pasted verbatim.

**Backend suite**

```text
$ .venv/Scripts/python -m pytest -s -v
platform win32 -- Python 3.13.7, pytest-9.2.0, pluggy-1.7.0
...
tests/test_slice3_e2e.py::test_03_failed_logins_raise_security_incident_without_raw_logs PASSED
...
========== 42 passed in 7.52s ==========
```

**Dashboard unit tests**

```text
$ cd dashboard && node --test src/chaos.test.js src/api.test.js src/timefmt.test.js
# tests 39
# pass 39
# fail 0
# cancelled 0
# skipped 0
# duration_ms 6522.8459
```

**Production build**

```text
$ cd dashboard && npm run build
✓ built in 1.81s
dist/index.html                   0.48 kB │ gzip:   0.32 kB
dist/assets/index-lX9lMvpB.css   31.58 kB │ gzip:   6.48 kB
dist/assets/index-DpnOy7mf.js   690.85 kB │ gzip: 202.63 kB
```

**Anti-drift check** — `git status --short --untracked-files=all` shows only whitelisted
frontend/launcher files changed; zero Python backend/test/spec files modified.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Proxy error `ssl3_get_record:wrong version number` | A plain-HTTP process is squatting on :8000 (the proxy speaks TLS to it) | Re-run `.\run_demo.ps1` — its pre-flight kills zombie listeners on 9000/8000/4001/4002/3000 |
| :3000 loads nothing although all windows look green | `npm run dev -- --port 3000` — PowerShell eats the bare `--`, so Vite gets `3000` as a folder name, ignores the port, and silently bumps off :3000 | The launcher already starts Vite directly: `node node_modules\vite\bin\vite.js --port 3000 --strictPort`. If you start it by hand, use that exact command |
| `ERROR: .venv\Scripts\python.exe not found` | venv missing | `python -m venv .venv`, then the pinned `pip install` command from [Quickstart](#quickstart--one-command) |
| Browser warns about the certificate | Self-signed demo cert | Expected; the dashboard proxy already uses `secure:false`. Regenerate with `.venv\Scripts\python scripts\gen_certs.py` (add `--lan-ip X` for LAN access) |
| Same incident appears twice | Duplicate `payload_id` handling | It shouldn't — ingest is `INSERT OR IGNORE`; check `duplicates_blocked_count` in `/api/v1/overview` |
| Another Vite app on :5173 interferes | Unrelated project (e.g. VulnChain) on Vite's default port | Ignore it — this dashboard is pinned to :3000 with `--strictPort` |
| Tests fail to import `shared` | Running pytest from the wrong directory | Run from the repo root; `pytest.ini` sets `pythonpath = .` |

---

## Repository layout

```text
smart-observability/
├── README.md                  ← this file
├── run_demo.ps1               ← one-click Windows launcher (5 windows, zombie pre-flight)
├── pytest.ini                 ← pythonpath = ., testpaths = tests
├── certs/                     ← cert.pem + key.pem (auto-generated, git-ignorable)
├── scripts/gen_certs.py       ← self-signed TLS generator (--lan-ip for LAN)
├── shared/
│   ├── contracts.py           ← FROZEN cross-tier contracts (additive changes only)
│   └── safe_errors.py         ← leak-proof 422 validation handler
├── collector/                 ← BOX 1 (customer network)
│   ├── main.py                ← FastAPI app, env-configured
│   ├── adapter.py             ← live-log tail + WS consumers, event normalisation
│   ├── scrubber.py            ← secret scan, pseudonymisation, redaction audit
│   ├── storage.py             ← SQLite WAL outbox
│   └── sender.py              ← egress drain (batch 25 / 0.25 s / heartbeat 10 s / backoff 1-2-4 cap 5)
├── saas/                      ← BOX 2 (central SaaS)
│   ├── main.py                ← FastAPI app: ingest, incidents, thresholds, SLA, WS
│   ├── auth.py                ← collector tokens + tenant JWTs
│   ├── db.py                  ← aiosqlite, 3 separate WAL DBs
│   ├── detector.py            ← pure-stdlib median/MAD z-scores
│   ├── aiops.py               ← health states + 45 s correlator
│   ├── watchdog.py            ← offline/stale detection (50/35/55 s)
│   └── remediation.py         ← approval-gated simulation plans
├── mock_stream/
│   └── stream_server.py       ← Box 0: 2 sites, 1 event/sec/source, 6 server-side chaos scenarios
├── dashboard/                 ← SLICE 4 React console (Vite + Tailwind v4 + Recharts)
│   ├── vite.config.js         ← proxies /api /ws /chaos /col-a /col-b
│   └── src/                   ← App.jsx, api.js, chaos.js, timefmt.js, 9 components, 3 test files
├── tests/                     ← 42 backend tests (4 files)
└── data/                      ← SQLite WAL DBs + live_host.log (runtime state)
```

---

## Known limitations

- **Demo-grade auth:** seeded tokens and the `demo123` demo password are for the demo
  only; `SAAS_JWT_SECRET` must be replaced outside the demo.
- **Self-signed TLS:** collectors run with `SAAS_TLS_VERIFY=false` in the demo; production
  would use a real CA chain.
- **Collector local API is unauthenticated** — it is a Box-1-internal surface by design.
- **SQLite, not Postgres:** chosen so the demo runs with zero external services; the
  schema is intentionally simple.
- **Windows launcher:** `run_demo.ps1` is PowerShell; the five services themselves are
  plain `uvicorn`/`vite` commands (see Manual startup) and run anywhere.
- **Dashboard bundle:** 690.85 kB (202.63 kB gzip) — Vite's chunk-size advisory suggests
  code-splitting; not an error, noted for honesty.
