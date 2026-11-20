import { Badge, HealthBadge, Panel } from './ui.jsx'
import { fmtAgo, fmtNum, fmtStamp, relSeconds } from '../timefmt.js'

// Panel C: one card per Box 1 collector. Online = heartbeat younger than 60s
// (the watchdog itself trips the collector offline at 50s).
export default function CollectorFleet({ collectors, now }) {
  return (
    <Panel
      title="Collector Fleet Health"
      subtitle="Box 1 edge collectors · watchdog grades heartbeat freshness"
      className="mt-3"
    >
      {collectors.length === 0 ? (
        <p className="py-4 text-center text-xs text-slate-500">
          No collectors registered for this tenant yet.
        </p>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {collectors.map((c) => {
            const age = relSeconds(c.last_heartbeat_utc, now)
            const online = age !== null && age < 60
            const rows = [
              ['Last heartbeat', `${fmtStamp(c.last_heartbeat_utc)} · ${fmtAgo(c.last_heartbeat_utc, now)}`],
              ['Version', c.version || '—'],
              ['CPU', `${fmtNum(c.cpu_pct)}%`],
              ['Memory', `${fmtNum(c.mem_mb, 0)} MB`],
              ['Outbox pending', String(c.outbox_pending_count ?? '—')],
              ['Config', c.config_status || '—'],
            ]
            return (
              <div
                key={c.collector_id}
                className="rounded-xl bg-panel-2/50 p-3 ring-1 ring-[var(--color-edge)]"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="num text-[13px] font-semibold text-slate-100">
                    {c.collector_id}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <HealthBadge state={c.health_state} />
                    <Badge
                      tone={
                        online
                          ? 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40'
                          : 'bg-red-500/15 text-red-300 ring-red-500/40'
                      }
                    >
                      {online ? 'Online' : 'Offline'}
                    </Badge>
                  </div>
                </div>
                <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                  {rows.map(([k, v]) => (
                    <div key={k}>
                      <span className="block text-[9px] font-bold uppercase tracking-wider text-slate-500">
                        {k}
                      </span>
                      <span className="num block text-slate-200">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Panel>
  )
}
