import { CHAOS_SCENARIOS } from '../constants.js'
import { Badge } from './ui.jsx'

// Collapsible chaos drawer. hospital-b drills ride the mock stream
// (/chaos/{scenario}); bank-a runs STREAM_MODE=live, so drills are synthesized
// in-browser as InternalRawEvent POSTs to /col-a/api/ingest-raw (see chaos.js).
export default function ChaosDrawer({
  open,
  tenant,
  tenantId,
  linkStatus,
  drillLog,
  onRunChaos,
  onToggleLink,
}) {
  if (!open) return null
  const status = linkStatus?.[tenant.collectorProxy] || null
  const linkOn = status ? Boolean(status.link_enabled) : null

  return (
    <section className="panel slide-up mt-3 border-accent/30">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--color-edge)] px-4 py-2.5">
        <div>
          <h2 className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
            Live Chaos & Outage Drill Drawer
          </h2>
          <p className="mt-0.5 text-[11px] text-slate-500">
            judge scenarios against {tenant.label} ({tenantId})
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {status && (
            <span className="num text-[10px] text-slate-500">
              {status.stream_mode} · outbox {status.pending_count}
            </span>
          )}
          {linkOn === null ? (
            <Badge>link status unknown</Badge>
          ) : linkOn ? (
            <Badge tone="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">link on</Badge>
          ) : (
            <Badge tone="bg-red-500/15 text-red-300 ring-red-500/40">link cut</Badge>
          )}
          <button
            type="button"
            onClick={onToggleLink}
            className="rounded-md bg-panel-2/80 px-2.5 py-1.5 text-[11px] font-semibold text-slate-200 ring-1 ring-[var(--color-edge)] transition hover:bg-panel-2 hover:ring-accent/40"
          >
            Cut / Restore Collector Link
          </button>
        </div>
      </header>

      <div className="p-4">
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          {CHAOS_SCENARIOS.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => onRunChaos(s.id)}
              className="rounded-lg bg-panel-2/70 px-3 py-2 text-left ring-1 ring-[var(--color-edge)] transition hover:bg-panel-2 hover:ring-accent/40"
            >
              <span className="block text-[12px] font-semibold text-slate-100">{s.label}</span>
              <span className="mt-0.5 block text-[10px] leading-snug text-slate-500">{s.blurb}</span>
            </button>
          ))}
        </div>

        <p className="mt-2.5 text-[10px] leading-relaxed text-slate-500">
          {tenantId === 'bank-a'
            ? 'Bank A runs STREAM_MODE=live: each drill is synthesized in-browser as InternalRawEvent POSTs to /col-a/api/ingest-raw, layered on top of real host telemetry.'
            : 'Hospital B runs on the mock stream: each drill POSTs /chaos/{scenario}?site=hospital-b.'}
        </p>

        {drillLog.length > 0 && (
          <div className="mt-3 max-h-36 overflow-y-auto rounded-lg bg-black/30 p-2 ring-1 ring-[var(--color-edge)]">
            {drillLog.map((line, i) => (
              <div key={`${line}-${i}`} className="num py-0.5 text-[10.5px] text-slate-400">
                {line}
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}
