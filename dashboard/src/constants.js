// Frozen tenant catalogue + shared UI maps. Endpoint URLs, enum values and
// field names mirror shared/contracts.py and saas/main.py verbatim.

export const TENANTS = {
  'bank-a': {
    tenantId: 'bank-a',
    label: 'Bank A',
    region: 'ap-south-1',
    regionLabel: 'India / Live Host',
    username: 'bank-a',
    password: 'demo123',
    collectorProxy: '/col-a',
    egressPanelUrl: 'http://localhost:4001',
    dbFile: 'saas_ap_south_1.db',
  },
  'hospital-b': {
    tenantId: 'hospital-b',
    label: 'Hospital B',
    region: 'eu-west-1',
    regionLabel: 'Europe / Stream',
    username: 'hospital-b',
    password: 'demo123',
    collectorProxy: '/col-b',
    egressPanelUrl: 'http://localhost:4002',
    dbFile: 'saas_eu_west_1.db',
  },
}

export const TENANT_ORDER = ['bank-a', 'hospital-b']

// HealthState enum values from shared/contracts.py.
export const HEALTH_BADGE = {
  Excellent: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  Good: 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/40',
  Fair: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  Poor: 'bg-red-500/15 text-red-300 ring-red-500/40',
}

export const SEVERITY_BADGE = {
  low: 'bg-slate-500/15 text-slate-300 ring-slate-400/40',
  medium: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  critical: 'bg-red-600/20 text-red-300 ring-red-500/40',
}

export const REMEDIATION_BADGE = {
  AWAITING_APPROVAL: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  APPROVED_EXECUTED: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  ROLLED_BACK: 'bg-sky-500/15 text-sky-300 ring-sky-500/40',
  POLICY_BLOCKED: 'bg-red-500/15 text-red-300 ring-red-500/40',
}

// Mock stream chaos scenarios (mock_stream/stream_server.py SCENARIOS).
export const CHAOS_SCENARIOS = [
  { id: 'secret', label: 'Inject Secret', blurb: 'Bearer token + password + private IP in a raw log line' },
  { id: 'failed_logins', label: '14x Failed Logins', blurb: 'Brute-force burst on one source' },
  { id: 'latency_spike', label: 'Latency Spike', blurb: 'Router RTT jumps past the fair ceiling' },
  { id: 'cpu_anomaly', label: 'CPU Anomaly', blurb: 'Server CPU/memory z-score breach' },
  { id: 'cascade_incident', label: 'Cascading Router+Server Incident', blurb: 'Uplink degrades, downstream follows 1.5s later' },
  { id: 'duplicate_payload', label: 'Duplicate Payload', blurb: 'Same forced_payload_id twice; Box 2 dedupes' },
  { id: 'out_of_order', label: 'Out-of-Order (-90s) Event', blurb: 'event_time_utc 90s in the past' },
]

// Mirror of mock_stream SECRET_LOG_LINE for the browser-side bank-a synthesis.
export const SECRET_LOG_LINE =
  'payment callback trace: Authorization: Bearer sk_live_98a7sd98a7sd ' +
  'password=hunter2xyz client_ip=10.20.4.15 result=declined'
