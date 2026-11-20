import { useState } from 'react'
import { api } from '../api.js'
import { REMEDIATION_BADGE, SEVERITY_BADGE } from '../constants.js'
import { Badge, EmptyNote, Panel, SignalBar } from './ui.jsx'
import { fmtNum, fmtStamp } from '../timefmt.js'

const STATUS_TONE = {
  OPEN: 'bg-amber-500/15 text-amber-300 ring-amber-500/40',
  MERGED: 'bg-cyan-500/15 text-cyan-300 ring-cyan-500/40',
  RESOLVED: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
}

const enableBtn =
  'rounded-md px-2.5 py-1.5 text-[11px] font-semibold ring-1 transition bg-emerald-500/20 text-emerald-200 ring-emerald-500/50 hover:bg-emerald-500/30'
const disableBtn =
  'cursor-not-allowed rounded-md px-2.5 py-1.5 text-[11px] font-semibold ring-1 bg-slate-800/40 text-slate-500 ring-slate-700/50'

function IncidentCard({ incident, jwt, onUpdated, onError }) {
  const [busy, setBusy] = useState(false)
  const ex = incident.explanation || {}
  const rem = incident.remediation || null
  const state = rem?.state
  const signals = ex.contributing_signals || []

  const act = async (run) => {
    if (busy) return
    setBusy(true)
    try {
      const record = await run()
      if (record) onUpdated(record)
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <article className="rounded-xl bg-panel-2/45 p-3.5 ring-1 ring-[var(--color-edge)]">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={SEVERITY_BADGE[incident.severity]?.tone}>
          {incident.severity}
        </Badge>
        <Badge tone={STATUS_TONE[incident.status] || undefined}>{incident.status}</Badge>
        {(incident.merged_alert_count ?? 0) > 0 && (
          <Badge tone="bg-cyan-500/15 text-cyan-300 ring-cyan-500/40">
            Merged Alerts: {incident.merged_alert_count}
          </Badge>
        )}
        <span className="num ml-auto text-[10px] text-slate-500">
          {incident.incident_id} · col {incident.collector_id} · alerted{' '}
          {fmtStamp(incident.alert_created_utc)}
        </span>
      </div>

      {ex.summary && <p className="mt-2 text-[12px] leading-snug text-slate-200">{ex.summary}</p>}

      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
        <span className="font-semibold text-slate-400">Root Cause:</span>
        <span className="num rounded bg-red-500/10 px-1.5 py-0.5 text-red-300 ring-1 ring-red-500/30">
          {incident.root_cause_source_id}
        </span>
        <span className="text-slate-500">· affected:</span>
        {(incident.affected_source_ids || []).map((id) => (
          <span
            key={id}
            className="num rounded bg-panel-2 px-1.5 py-0.5 text-slate-300 ring-1 ring-[var(--color-edge)]"
          >
            {id}
          </span>
        ))}
      </div>

      <div className="mt-2.5 text-[9.5px] font-bold uppercase tracking-wider text-slate-500">
        Statistical Basis (Zero ML / HST)
      </div>
      <div className="mt-1 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {[
          ['max z-score', fmtNum(ex.max_z_score, 2)],
          ['joint L2 z', fmtNum(ex.joint_l2_z, 2)],
          ['elevated metrics', String(ex.elevated_metric_count ?? '—')],
          ['confidence', `${fmtNum(ex.confidence_pct, 0)}%`],
        ].map(([k, v]) => (
          <div
            key={k}
            className="rounded-md bg-panel-2/60 px-2 py-1.5 ring-1 ring-[var(--color-edge)]"
          >
            <div className="text-[9px] font-bold uppercase tracking-wider text-slate-500">{k}</div>
            <div className="num text-[13px] font-semibold text-slate-100">{v}</div>
          </div>
        ))}
      </div>

      {signals.length > 0 && (
        <div className="mt-2.5">
          <div className="text-[9.5px] font-bold uppercase tracking-wider text-slate-500">
            Contributing Signals (weights sum to 100%)
          </div>
          <div className="mt-1 space-y-1">
            {signals.map((sig, i) => (
              <SignalBar
                key={`${sig.source_id}-${sig.metric}-${i}`}
                label={`${sig.source_id} · ${sig.metric}`}
                detail={`${fmtNum(sig.value)} vs baseline ${fmtNum(sig.baseline)} · z ${fmtNum(sig.z_score, 2)}`}
                weightPct={sig.weight_pct}
              />
            ))}
          </div>
        </div>
      )}

      {ex.recommended_action && (
        <p className="mt-2 text-[11.5px] text-slate-300">
          <span className="font-semibold text-accent">Recommended action:</span>{' '}
          {ex.recommended_action}
        </p>
      )}
      {ex.reasoning_path && (
        <p className="mt-1 text-[11px] leading-snug text-slate-400">
          <span className="font-semibold text-slate-500">Reasoning path:</span> {ex.reasoning_path}
        </p>
      )}

      <div className="mt-3 rounded-xl bg-black/25 p-3 ring-1 ring-[var(--color-edge)]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[9.5px] font-bold uppercase tracking-wider text-slate-500">
            Safe Remediation Simulator
          </span>
          {rem ? (
            <>
              <Badge
                tone={
                  rem.policy_check_passed
                    ? 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40'
                    : 'bg-red-500/15 text-red-300 ring-red-500/40'
                }
              >
                {rem.policy_check_passed ? 'POLICY PASSED' : 'POLICY BLOCKED'}
              </Badge>
              {rem.policy_rule_matched && <Badge>rule: {rem.policy_rule_matched}</Badge>}
              <Badge tone={REMEDIATION_BADGE[state]?.tone}>{state}</Badge>
            </>
          ) : (
            <span className="text-[10.5px] text-slate-500">
              no remediation proposed for this incident yet
            </span>
          )}
        </div>

        {rem && (
          <>
            {rem.proposed_action && (
              <p className="mt-1.5 text-[11.5px] text-slate-300">
                <span className="font-semibold text-slate-500">Proposed:</span>{' '}
                {rem.proposed_action}
              </p>
            )}
            {rem.rollback_plan && (
              <p className="mt-0.5 text-[11px] text-slate-400">
                <span className="font-semibold text-slate-500">Rollback plan:</span>{' '}
                {rem.rollback_plan}
              </p>
            )}
            <div className="mt-2 flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy || state !== 'AWAITING_APPROVAL'}
                onClick={() => act(() => api.approveIncident(jwt, incident.incident_id))}
                className={state === 'AWAITING_APPROVAL' && !busy ? enableBtn : disableBtn}
              >
                {busy ? 'Working…' : 'Approve Remediation'}
              </button>
              <button
                type="button"
                disabled={busy || state !== 'APPROVED_EXECUTED'}
                onClick={() => act(() => api.rollbackIncident(jwt, incident.incident_id))}
                className={state === 'APPROVED_EXECUTED' && !busy ? enableBtn : disableBtn}
              >
                Rollback
              </button>
            </div>
            {rem.audit_trail?.length > 0 && (
              <div className="mt-2 rounded-lg bg-black/30 p-2 ring-1 ring-[var(--color-edge)]">
                <div className="text-[9.5px] font-bold uppercase tracking-wider text-slate-500">
                  Immutable Audit Trail
                </div>
                <ul className="mt-1 space-y-0.5">
                  {rem.audit_trail.map((a, i) => (
                    <li key={`${a.timestamp_utc}-${i}`} className="num text-[10.5px] text-slate-400">
                      {a.timestamp_utc} · {a.actor} · {a.action}
                      {a.details ? ` · ${a.details}` : ''}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </div>
    </article>
  )
}

// Panel E: explainable AIOps incidents with the human-in-the-loop remediation flow.
export default function IncidentsPanel({ incidents, jwt, onUpdated, onError }) {
  const sorted = [...incidents].sort((a, b) =>
    String(b.alert_created_utc || '').localeCompare(String(a.alert_created_utc || '')),
  )
  return (
    <Panel
      title="Explainable AIOps Incidents & Safe Remediation"
      subtitle="statistical correlation only · median/MAD z-scores, no ML in the loop"
      className="mt-3"
    >
      {sorted.length === 0 ? (
        <EmptyNote>
          No incidents correlated yet — fire a chaos drill or wait for a threshold breach.
        </EmptyNote>
      ) : (
        <div className="space-y-3">
          {sorted.map((incident) => (
            <IncidentCard
              key={incident.incident_id}
              incident={incident}
              jwt={jwt}
              onUpdated={onUpdated}
              onError={onError}
            />
          ))}
        </div>
      )}
    </Panel>
  )
}
