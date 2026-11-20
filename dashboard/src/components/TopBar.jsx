import { Activity, Clock, ExternalLink, SlidersHorizontal, Zap } from 'lucide-react'

const WS_TONE = {
  live: { dot: 'bg-emerald-400 live-dot', text: 'text-emerald-300', label: 'WS LIVE' },
  connecting: { dot: 'bg-amber-400 live-dot', text: 'text-amber-300', label: 'WS CONNECTING' },
  offline: { dot: 'bg-red-500', text: 'text-red-300', label: 'WS OFFLINE' },
}

const btn =
  'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-[11px] font-semibold ring-1 transition'

export default function TopBar({
  tenant,
  tenantId,
  tenants,
  tenantOrder,
  onSwitch,
  tzMode,
  onToggleTz,
  onOpenThresholds,
  chaosOpen,
  onToggleChaos,
  wsState,
}) {
  const ws = WS_TONE[wsState] || WS_TONE.offline
  return (
    <header className="panel sticky top-2 z-30 mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
      <div className="flex items-center gap-2">
        <span className="grid h-7 w-7 place-items-center rounded-lg bg-accent/15 text-accent ring-1 ring-accent/40">
          <Activity size={15} />
        </span>
        <div>
          <div className="text-[13px] font-bold leading-tight text-slate-100">
            SentinelOps SaaS Console
          </div>
          <div className="text-[10px] uppercase tracking-[0.14em] text-slate-500">
            multi-tenant observability
          </div>
        </div>
      </div>

      <div className="flex items-center gap-1.5">
        {tenantOrder.map((id) => {
          const t = tenants[id]
          const active = id === tenantId
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSwitch(id)}
              disabled={active}
              title={`Switch to ${t.label} (${t.region}) — fresh JWT, new WS, full state reset`}
              className={`rounded-lg px-2.5 py-1.5 text-left ring-1 transition ${
                active
                  ? 'bg-accent/15 text-accent ring-accent/50'
                  : 'bg-panel-2/60 text-slate-300 ring-[var(--color-edge)] hover:bg-panel-2 hover:text-slate-100'
              }`}
            >
              <span className="block text-[11px] font-semibold leading-tight">{t.label}</span>
              <span className="num block text-[9px] leading-tight opacity-70">{t.region}</span>
            </button>
          )
        })}
      </div>

      <div className="ml-auto flex flex-wrap items-center gap-2">
        <span className="rounded-md bg-panel-2/70 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-slate-400 ring-1 ring-[var(--color-edge)]">
          {tenant.regionLabel}
        </span>
        <span
          className={`inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide ${ws.text}`}
        >
          <span className={`h-2 w-2 rounded-full ${ws.dot}`} /> {ws.label}
        </span>
        <button
          type="button"
          onClick={onToggleTz}
          title="Toggle chart axes and timestamps between UTC and the source timezone"
          className={`${btn} bg-panel-2/70 text-slate-300 ring-[var(--color-edge)] hover:text-slate-100`}
        >
          <Clock size={12} /> TZ {tzMode === 'UTC' ? 'UTC' : 'Source TZ'}
        </button>
        <button
          type="button"
          onClick={onOpenThresholds}
          className={`${btn} bg-panel-2/70 text-slate-300 ring-[var(--color-edge)] hover:text-slate-100`}
        >
          <SlidersHorizontal size={12} /> Thresholds
        </button>
        <button
          type="button"
          onClick={onToggleChaos}
          className={`${btn} ${
            chaosOpen
              ? 'bg-accent/15 text-accent ring-accent/50'
              : 'bg-panel-2/70 text-slate-300 ring-[var(--color-edge)] hover:text-slate-100'
          }`}
        >
          <Zap size={12} /> Chaos Drills
        </button>
        <a
          href={tenant.egressPanelUrl}
          target="_blank"
          rel="noreferrer"
          className={`${btn} bg-panel-2/70 text-slate-300 ring-[var(--color-edge)] hover:text-slate-100`}
        >
          <ExternalLink size={12} /> Egress Proof
        </a>
      </div>
    </header>
  )
}
