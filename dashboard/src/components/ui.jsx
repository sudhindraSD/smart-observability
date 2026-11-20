import { HEALTH_BADGE } from '../constants.js'

export function Badge({ children, tone = '', className = '' }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ring-1 ring-inset ${
        tone || 'bg-slate-700/30 text-slate-300 ring-slate-500/40'
      } ${className}`}
    >
      {children}
    </span>
  )
}

export function HealthBadge({ state }) {
  return <Badge tone={HEALTH_BADGE[state] || ''}>{state || 'Unknown'}</Badge>
}

export function Panel({ title, subtitle, right, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <header className="flex items-center justify-between gap-3 border-b border-[var(--color-edge)] px-4 py-2.5">
          <div>
            <h2 className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
              {title}
            </h2>
            {subtitle && <p className="mt-0.5 text-[11px] text-slate-500">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Metric({ label, value, sub, tone = 'text-slate-100', className = '' }) {
  return (
    <div className={className}>
      <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500">
        {label}
      </div>
      <div className={`num mt-0.5 text-lg font-semibold leading-tight ${tone}`}>{value}</div>
      {sub && <div className="mt-0.5 text-[11px] text-slate-500">{sub}</div>}
    </div>
  )
}

export function SignalBar({ label, detail, weightPct, tone = 'bg-accent' }) {
  return (
    <div className="py-1.5">
      <div className="flex items-baseline justify-between gap-2 text-[11px]">
        <span className="num text-slate-300">{label}</span>
        <span className="num text-slate-500">{detail}</span>
        <span className="num font-semibold text-slate-200">{weightPct}%</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div
          className={`h-full rounded-full ${tone}`}
          style={{ width: `${Math.min(100, Math.max(2, weightPct))}%` }}
        />
      </div>
    </div>
  )
}

export function Spinner({ label = 'Loading…' }) {
  return (
    <div className="flex items-center gap-2 py-6 text-slate-500">
      <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-600 border-t-accent" />
      <span className="text-xs">{label}</span>
    </div>
  )
}

export function EmptyNote({ children }) {
  return <p className="py-6 text-center text-xs text-slate-500">{children}</p>
}
