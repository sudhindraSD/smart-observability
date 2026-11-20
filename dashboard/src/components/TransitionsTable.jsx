import { EmptyNote, Panel } from './ui.jsx'
import { fmtStamp } from '../timefmt.js'

function transitionTone(t) {
  const s = String(t.new_state || '')
  if (s === 'Poor' || s === 'down' || s === 'critical') return 'text-red-300'
  if (s === 'Fair' || s === 'degraded') return 'text-amber-300'
  if (s === 'Excellent' || s === 'Good' || s === 'up') return 'text-emerald-300'
  return 'text-slate-200'
}

// Panel F: watchdog + correlator state-machine history, refreshed by
// /api/v1/overview polls and live WS `transition` frames.
export default function TransitionsTable({ transitions, tzMode }) {
  return (
    <Panel
      title="Health State Transition History"
      subtitle="watchdog + correlator state machine · live via WS transition frames"
      className="mt-3"
    >
      {transitions.length === 0 ? (
        <EmptyNote>No transitions recorded yet.</EmptyNote>
      ) : (
        <div className="max-h-80 overflow-y-auto">
          <table className="w-full border-collapse text-left text-[11px]">
            <thead className="sticky top-0 bg-[var(--color-panel)]">
              <tr className="text-[9.5px] uppercase tracking-wider text-slate-500">
                <th className="border-b border-[var(--color-edge)] py-1.5 pr-3 font-bold">Time</th>
                <th className="border-b border-[var(--color-edge)] py-1.5 pr-3 font-bold">
                  Entity
                </th>
                <th className="border-b border-[var(--color-edge)] py-1.5 pr-3 font-bold">ID</th>
                <th className="border-b border-[var(--color-edge)] py-1.5 pr-3 font-bold">
                  Transition
                </th>
                <th className="border-b border-[var(--color-edge)] py-1.5 pr-3 font-bold">
                  Reason
                </th>
              </tr>
            </thead>
            <tbody>
              {transitions.map((t) => (
                <tr
                  key={`${t.id ?? ''}-${t.transition_time_utc}-${t.entity_id}-${t.new_state}`}
                  className="border-b border-[var(--color-edge)]/50 last:border-0"
                >
                  <td className="num py-1.5 pr-3 whitespace-nowrap text-slate-400">
                    {fmtStamp(t.transition_time_utc, tzMode)}
                  </td>
                  <td className="py-1.5 pr-3 text-slate-300">{t.entity_type}</td>
                  <td className="num py-1.5 pr-3 text-slate-300">{t.entity_id}</td>
                  <td className={`num py-1.5 pr-3 font-semibold ${transitionTone(t)}`}>
                    {t.old_state} → {t.new_state}
                  </td>
                  <td className="py-1.5 pr-3 text-slate-400">{t.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}
