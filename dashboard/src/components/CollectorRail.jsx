import { Server, Unplug } from 'lucide-react'
import { fmtAgo, relSeconds } from '../timefmt.js'
import { Skeleton, Status } from './ui.jsx'
import { HEALTH_TONE } from './tones.js'

function fmtInt(n) {
  return n === null || n === undefined ? '—' : Number(n).toLocaleString('en-US')
}

// Vertical bar of the inverted L: both Box 1 edge collectors, read straight
// from their own /api/status (link, outbox, raw vs sent) plus, for the active
// tenant, Box 2's heartbeat view of the same collector.
function CollectorCard({ tenant, status, heartbeat, active, onSelectTenant, now }) {
  const loading = status === undefined
  const unreachable = status === null
  const linkUp = status?.link_enabled
  const hbAge = heartbeat ? relSeconds(heartbeat.last_heartbeat_utc, now) : null

  let tone = 'neutral'
  let label = 'Checking'
  if (unreachable) {
    tone = 'crit'
    label = 'Unreachable'
  } else if (status && !linkUp) {
    tone = 'warn'
    label = 'Link cut · buffering'
  } else if (status) {
    tone = 'ok'
    label = 'Egress live'
  }

  return (
    <li>
      <button
        type="button"
        onClick={() => onSelectTenant(tenant.tenantId)}
        aria-current={active ? 'true' : undefined}
        className={`w-full rounded-md border px-3 py-3 text-left transition-colors duration-150 ${
          active
            ? 'border-line-strong bg-raised'
            : 'border-transparent hover:border-line hover:bg-surface'
        }`}
      >
        <div className="flex items-center gap-2">
          {unreachable ? (
            <Unplug size={15} className="text-crit" aria-hidden="true" />
          ) : (
            <Server size={15} className="text-subtle" aria-hidden="true" />
          )}
          <span className="text-body font-semibold text-head">{tenant.label}</span>
          <span className="num ml-auto text-label text-subtle">{tenant.region}</span>
        </div>
        <div className="num mt-0.5 pl-[23px] text-label text-subtle">
          {status?.collector_id || '—'} · {status?.stream_mode || tenant.regionLabel}
        </div>

        <div className="mt-2 pl-[23px]">
          {loading ? (
            <Skeleton className="h-4 w-28" />
          ) : (
            <Status tone={tone} pulse={tone === 'ok'}>
              {label}
            </Status>
          )}
        </div>

        {status && (
          <dl className="mt-3 grid grid-cols-3 gap-2 pl-[23px]">
            <div>
              <dt className="eyebrow">Raw</dt>
              <dd className="num text-meta text-fg">{fmtInt(status.raw_count)}</dd>
            </div>
            <div>
              <dt className="eyebrow">Sent</dt>
              <dd className="num text-meta text-fg">{fmtInt(status.total_sent_count)}</dd>
            </div>
            <div>
              <dt className="eyebrow">Outbox</dt>
              <dd
                className={`num text-meta ${status.pending_count > 0 && !linkUp ? 'text-warn' : 'text-fg'}`}
              >
                {fmtInt(status.pending_count)}
              </dd>
            </div>
          </dl>
        )}

        {active && heartbeat && (
          <div className="mt-3 border-t border-line pt-2 pl-[23px] text-label text-subtle">
            <div className="flex items-center justify-between gap-2">
              <span>Box 2 heartbeat</span>
              <Status tone={HEALTH_TONE[heartbeat.health_state] || 'neutral'}>
                {heartbeat.offline_detected_utc ? 'Offline' : heartbeat.health_state}
              </Status>
            </div>
            <div className="num mt-1 flex justify-between gap-2">
              <span>{hbAge === null ? '—' : fmtAgo(heartbeat.last_heartbeat_utc, now)}</span>
              <span>
                cpu {heartbeat.cpu_pct ?? '—'}% · {heartbeat.config_status}
              </span>
            </div>
          </div>
        )}
      </button>
    </li>
  )
}

export default function CollectorRail({
  tenants,
  tenantOrder,
  tenantId,
  linkStatus,
  collectors,
  onSelectTenant,
  now,
}) {
  return (
    <nav
      aria-label="Box 1 edge collectors"
      className="border-b border-line bg-canvas lg:sticky lg:top-14 lg:h-[calc(100vh-3.5rem)] lg:w-64 lg:shrink-0 lg:overflow-y-auto lg:border-b-0 lg:border-r"
    >
      <div className="px-4 pb-2 pt-4">
        <p className="eyebrow">Box 1 · Edge collectors</p>
        <p className="mt-1 text-meta text-subtle">
          Telemetry is scrubbed here. Only redacted payloads cross to Box 2.
        </p>
      </div>
      <ul className="grid gap-1 px-2 pb-4 sm:grid-cols-2 lg:grid-cols-1">
        {tenantOrder.map((id) => {
          const t = tenants[id]
          const status = linkStatus[t.collectorProxy]
          const heartbeat =
            id === tenantId && status
              ? collectors.find((c) => c.collector_id === status.collector_id) || collectors[0]
              : null
          return (
            <CollectorCard
              key={id}
              tenant={t}
              status={status}
              heartbeat={heartbeat}
              active={id === tenantId}
              onSelectTenant={onSelectTenant}
              now={now}
            />
          )
        })}
      </ul>
    </nav>
  )
}
