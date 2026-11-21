import { ArrowRight } from 'lucide-react'
import { Skeleton } from './ui.jsx'

function fmtInt(n) {
  return n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US')
}

function fmtSec(n) {
  return n === null || n === undefined ? '—' : `${Number(n).toFixed(2)}s`
}

function Stat({ label, value, sub, tone = 'text-head' }) {
  return (
    <div className="min-w-0">
      <div className="eyebrow truncate">{label}</div>
      <div className={`num mt-1 text-heading font-semibold ${tone}`}>{value}</div>
      {sub && <div className="mt-0.5 truncate text-label text-subtle">{sub}</div>}
    </div>
  )
}

// The two-tier story in one row: edge raw -> scrubbed egress -> Box 2 receipt,
// then delivery guarantees and alert latency. Every number is from
// /col-*/api/status and /api/v1/sla-metrics.
export default function PipelineBand({ tenant, collectorStatus, sla, liveP95, sampleCount }) {
  if (!sla) {
    return (
      <div className="grid grid-cols-2 gap-4 rounded-md border border-line bg-surface p-4 md:grid-cols-4 xl:grid-cols-7">
        {Array.from({ length: 7 }, (_, i) => (
          <div key={i}>
            <Skeleton className="h-3 w-16" />
            <Skeleton className="mt-2 h-6 w-20" />
          </div>
        ))}
      </div>
    )
  }

  const lost = sla.lost_count ?? 0
  const p95 = sla.alert_latency_p95_sec
  return (
    <section
      aria-label="Box 1 to Box 2 pipeline"
      className="rounded-md border border-line bg-surface shadow-1"
    >
      <div className="grid grid-cols-2 gap-x-4 gap-y-4 p-4 md:grid-cols-4 xl:grid-cols-[1fr_auto_1fr_auto_1fr_1fr_1fr_1fr_1fr]">
        <Stat
          label="Box 1 raw events"
          value={fmtInt(collectorStatus?.raw_count)}
          sub={`${tenant.label} edge`}
        />
        <ArrowRight
          size={16}
          className="hidden self-center text-subtle xl:block"
          aria-hidden="true"
        />
        <Stat
          label="Scrubbed + sent"
          value={fmtInt(sla.total_sent_count)}
          sub="redacted payloads"
        />
        <ArrowRight
          size={16}
          className="hidden self-center text-subtle xl:block"
          aria-hidden="true"
        />
        <Stat
          label="Box 2 received"
          value={fmtInt(sla.total_received_count)}
          sub={tenant.dbFile}
        />
        <Stat
          label="Lost"
          value={fmtInt(lost)}
          tone={lost > 0 ? 'text-crit' : 'text-ok'}
          sub={`${fmtInt(sla.backlog_replayed_count)} replayed`}
        />
        <Stat
          label="Dupes blocked"
          value={fmtInt(sla.duplicates_blocked_count)}
          sub="idempotent on payload_id"
        />
        <Stat
          label="Alert p95"
          value={fmtSec(p95)}
          tone={p95 !== null && p95 > 10 ? 'text-warn' : 'text-head'}
          sub={`latest ${fmtSec(sla.alert_latency_latest_sec)}`}
        />
        <Stat
          label="Live render p95"
          value={liveP95 === null ? '—' : `${liveP95.toFixed(2)}s`}
          sub={sampleCount ? `${sampleCount} WS frames` : 'waiting for frames'}
        />
      </div>
    </section>
  )
}
