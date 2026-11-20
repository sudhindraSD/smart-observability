import { Metric } from './ui.jsx'

const fmtSec = (v) =>
  v === null || v === undefined || Number.isNaN(Number(v)) ? '—' : `${Number(v).toFixed(1)}s`

function latencyTone(sec, greenMax, amberMax) {
  if (sec === null || sec === undefined || Number.isNaN(Number(sec))) return 'text-slate-100'
  const n = Number(sec)
  if (n <= greenMax) return 'text-emerald-300'
  if (n <= amberMax) return 'text-amber-300'
  return 'text-red-300'
}

function Card({ children }) {
  return <div className="panel px-4 py-3">{children}</div>
}

const wsCopy = {
  live: { dot: 'bg-emerald-400 live-dot', text: 'text-emerald-300', label: 'WS live' },
  connecting: { dot: 'bg-amber-400 live-dot', text: 'text-amber-300', label: 'WS connecting' },
  offline: { dot: 'bg-red-500', text: 'text-red-300', label: 'WS offline' },
}

// Panel A: always-visible SLA & reliability proof strip.
export default function SlaStrip({ tenant, sla, liveP95, sampleCount, wsState }) {
  const ws = wsCopy[wsState] || wsCopy.offline
  const p95 = sla?.alert_latency_p95_sec
  const latest = sla?.alert_latency_latest_sec
  const offline = sla?.collector_offline_detection_sec
  const lost = sla?.lost_count

  return (
    <section className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
      <Card>
        <Metric
          label="Collection → Dashboard"
          value={liveP95 === null ? '—' : `${liveP95.toFixed(1)}s`}
          tone={liveP95 === null ? 'text-slate-100' : latencyTone(liveP95, 10, 15)}
          sub={`browser p95 T5−T0 · n=${sampleCount} live WS frames`}
        />
      </Card>

      <Card>
        <Metric
          label="Breach → Alert (T4−T0)"
          value={fmtSec(p95)}
          tone={latencyTone(p95, 15, 30)}
          sub={`p95 · latest ${fmtSec(latest)} · target ≤ 15.0s`}
        />
      </Card>

      <Card>
        <Metric
          label="Collector Offline Detection"
          value={fmtSec(offline)}
          tone={latencyTone(offline, 60, 120)}
          sub="target ≤ 60s · watchdog trips at 50s"
        />
      </Card>

      <Card>
        <Metric
          label="Backlog & Integrity"
          value={`${sla?.total_sent_count ?? '—'} sent · ${sla?.total_received_count ?? '—'} recv`}
        />
        <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]">
          <span className={`num font-semibold ${lost === 0 ? 'text-emerald-300' : 'text-red-300'}`}>
            Lost: {lost ?? '—'}
          </span>
          <span className="num text-slate-400">
            Dupes blocked: {sla?.duplicates_blocked_count ?? '—'}
          </span>
          <span className="num text-slate-400">
            Backlog replayed: {sla?.backlog_replayed_count ?? '—'}
          </span>
        </div>
      </Card>

      <Card>
        <Metric label="Regional Data Residency" value={tenant.region} tone="text-accent" />
        <div className="num mt-1.5 text-[11px] text-slate-400">
          {sla?.regional_db_file || tenant.dbFile}
        </div>
        <div className="mt-1 flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-slate-500">
          <span className={`h-1.5 w-1.5 rounded-full ${ws.dot}`} /> {ws.label} · rows never leave
          this regional DB file
        </div>
      </Card>
    </section>
  )
}
