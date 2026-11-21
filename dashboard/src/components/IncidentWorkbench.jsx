import { useMemo, useState } from 'react'
import { CheckCircle2, GitMerge, RotateCcw, ShieldAlert } from 'lucide-react'
import { api } from '../api.js'
import { fmtAgo, fmtNum, fmtStamp } from '../timefmt.js'
import {
  Button,
  EmptyState,
  KeyValue,
  SectionHeader,
  SignalBar,
  Skeleton,
  Status,
  Tag,
} from './ui.jsx'
import { REMEDIATION_LABEL, REMEDIATION_TONE, SEVERITY_TONE } from './tones.js'

const QUEUE_CAP = 25

const FILTERS = [

  { id: 'needs', label: 'Needs approval' },
  { id: 'OPEN', label: 'Open' },
  { id: 'all', label: 'All' },
]

const MERGE_RE = /^merged alert from (\S+) \(max_z=([\d.]+)\) at (\S+)$/

// reasoning_path is one '; '-joined string from saas/aiops.py: the detector
// steps first, then one "merged alert from <src> (max_z=..) at <iso>" per merge.
function splitReasoning(path) {
  const steps = []
  const merges = []
  for (const part of String(path || '').split('; ')) {
    const text = part.trim()
    if (!text) continue
    const m = MERGE_RE.exec(text)
    if (m) merges.push({ sourceId: m[1], maxZ: Number(m[2]), at: m[3] })
    else steps.push(text)
  }
  return { steps, merges }
}

function matchesFilter(inc, filter) {
  if (filter === 'needs') return inc.remediation?.state === 'AWAITING_APPROVAL'
  if (filter === 'OPEN') return inc.status === 'OPEN'
  return true
}

function QueueRow({ inc, selected, onSelect, now }) {
  const rem = inc.remediation?.state
  return (
    <li>
      <button
        type="button"
        onClick={() => onSelect(inc.incident_id)}
        aria-current={selected ? 'true' : undefined}
        className={`relative w-full border-b border-line px-4 py-3 text-left transition-colors duration-150 ${
          selected ? 'bg-raised' : 'hover:bg-hover/60'
        }`}
      >
        {selected && (
          <span aria-hidden="true" className="absolute inset-y-0 left-0 w-0.5 bg-accent" />
        )}
        <div className="flex items-center gap-2">
          <Status tone={SEVERITY_TONE[inc.severity]}>
            <span className="capitalize">{inc.severity}</span>
          </Status>
          <span className="num truncate text-label text-subtle">{inc.incident_id}</span>
          <span className="num ml-auto shrink-0 text-label text-subtle">
            {fmtAgo(inc.alert_created_utc, now)}
          </span>
        </div>
        <div className="mt-1 flex items-center gap-2">
          <span className="num truncate text-body font-medium text-head">
            {inc.root_cause_source_id}
          </span>
          {(inc.merged_alert_count ?? 0) > 1 && (
            <span className="num inline-flex items-center gap-1 text-label text-muted">
              <GitMerge size={12} aria-hidden="true" />
              {inc.merged_alert_count}
            </span>
          )}
        </div>
        <div className="mt-1 flex items-center gap-2 text-label text-subtle">
          <span>{inc.status}</span>
          {rem && (
            <>
              <span aria-hidden="true">·</span>
              <Status tone={REMEDIATION_TONE[rem]} className="!text-label">
                {REMEDIATION_LABEL[rem] || rem}
              </Status>
            </>
          )}
        </div>
      </button>
    </li>
  )
}

function RemediationBlock({ incident, jwt, onUpdated, onError }) {
  const [busy, setBusy] = useState(null)
  const [done, setDone] = useState(null)
  const rem = incident.remediation
  const state = rem?.state

  const act = async (kind) => {
    if (busy) return
    setBusy(kind)
    setDone(null)
    try {
      const record =
        kind === 'approve'
          ? await api.approveIncident(jwt, incident.incident_id)
          : await api.rollbackIncident(jwt, incident.incident_id)
      if (record) onUpdated(record)
      setDone(kind === 'approve' ? 'Remediation executed.' : 'Remediation rolled back.')
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(null)
    }
  }

  if (!rem) {
    return (
      <p className="text-meta text-subtle">
        No remediation proposed. The policy engine only proposes reversible, simulated actions.
      </p>
    )
  }

  return (
    <div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Status tone={REMEDIATION_TONE[state]}>{REMEDIATION_LABEL[state] || state}</Status>
        <Status tone={rem.policy_check_passed ? 'ok' : 'crit'}>
          {rem.policy_check_passed ? 'Policy passed' : 'Policy blocked'}
        </Status>
        {rem.policy_rule_matched && <Tag className="num">{rem.policy_rule_matched}</Tag>}
      </div>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        <KeyValue label="Proposed action" value={rem.proposed_action || '—'} />
        <KeyValue label="Action ID" value={rem.action_id || '—'} />
      </dl>
      {rem.rollback_plan && (
        <p className="mt-3 text-meta text-muted">
          <span className="font-medium text-fg">Rollback plan: </span>
          {rem.rollback_plan}
        </p>
      )}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <Button
          variant="primary"
          disabled={Boolean(busy) || state !== 'AWAITING_APPROVAL'}
          onClick={() => act('approve')}
        >
          <CheckCircle2 size={15} aria-hidden="true" />
          {busy === 'approve' ? 'Approving…' : 'Approve remediation'}
        </Button>
        <Button
          variant="secondary"
          disabled={Boolean(busy) || state !== 'APPROVED_EXECUTED'}
          onClick={() => act('rollback')}
        >
          <RotateCcw size={15} aria-hidden="true" />
          {busy === 'rollback' ? 'Rolling back…' : 'Roll back'}
        </Button>
        <span role="status" className="text-meta text-ok">
          {done}
        </span>
      </div>
      {state === 'POLICY_BLOCKED' && (
        <p className="mt-2 text-meta text-subtle">
          Blocked by policy, so approval is disabled. Nothing will run against the edge.
        </p>
      )}
    </div>
  )
}

function MergeTimeline({ merges, tzMode }) {
  const [showAll, setShowAll] = useState(false)
  if (merges.length === 0) return null
  const visible = showAll ? merges : merges.slice(0, 6)
  return (
    <div>
      <ol className="relative ml-1 border-l border-line">
        {visible.map((m, i) => (
          <li key={`${m.at}-${i}`} className="relative py-1.5 pl-4">
            <span
              aria-hidden="true"
              className="absolute -left-[3.5px] top-3 h-1.5 w-1.5 rounded-full bg-line-strong"
            />
            <div className="flex flex-wrap items-baseline gap-x-3 text-meta">
              <span className="num text-subtle">{fmtStamp(m.at, tzMode)}</span>
              <span className="num text-fg">{m.sourceId}</span>
              <span className="num text-muted">max z {fmtNum(m.maxZ, 2)}</span>
            </div>
          </li>
        ))}
      </ol>
      {merges.length > 6 && (
        <Button variant="ghost" className="mt-1" onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Show fewer' : `Show all ${merges.length} merged alerts`}
        </Button>
      )}
    </div>
  )
}

function Detail({ incident, jwt, onUpdated, onError, tzMode, egressSlot }) {
  const ex = incident.explanation || {}
  const signals = ex.contributing_signals || []
  const { steps, merges } = useMemo(() => splitReasoning(ex.reasoning_path), [ex.reasoning_path])
  return (
    <article key={incident.incident_id} className="enter" aria-labelledby="incident-title">
      <div className="border-b border-line px-5 py-4">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Status tone={SEVERITY_TONE[incident.severity]}>
            <span className="capitalize">{incident.severity}</span>
          </Status>
          <span className="text-meta text-subtle">{incident.status}</span>
          <span className="num text-meta text-subtle">{incident.incident_id}</span>
          <span className="num ml-auto text-meta text-subtle">
            alerted {fmtStamp(incident.alert_created_utc, tzMode)}
          </span>
        </div>
        <h2
          id="incident-title"
          className="mt-2 text-heading font-semibold tracking-tight text-head"
        >
          {ex.summary || `Incident on ${incident.root_cause_source_id}`}
        </h2>
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-meta">
          <span className="text-subtle">Root cause</span>
          <Tag className="num !border-crit/40 !text-crit">{incident.root_cause_source_id}</Tag>
          <span className="ml-1 text-subtle">Affected</span>
          {(incident.affected_source_ids || []).map((id) => (
            <Tag key={id} className="num">
              {id}
            </Tag>
          ))}
        </div>
      </div>

      {egressSlot}

      <section className="border-b border-line px-5 py-4" aria-labelledby="rem-h">
        <h3 id="rem-h" className="eyebrow mb-3 flex items-center gap-1.5">
          <ShieldAlert size={13} aria-hidden="true" /> 02 · Remediation · approval gated
        </h3>
        <RemediationBlock
          key={incident.incident_id}
          incident={incident}
          jwt={jwt}
          onUpdated={onUpdated}
          onError={onError}
        />
      </section>

      <section className="border-b border-line px-5 py-4" aria-labelledby="basis-h">
        <h3 id="basis-h" className="eyebrow">
          03 · Statistical basis · robust z-score, no ML
        </h3>
        <dl className="mt-3 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <KeyValue label="Max z" value={fmtNum(ex.max_z_score, 2)} />
          <KeyValue label="Joint L2 z" value={fmtNum(ex.joint_l2_z, 2)} />
          <KeyValue label="Elevated metrics" value={String(ex.elevated_metric_count ?? '—')} />
          <KeyValue label="Confidence" value={`${fmtNum(ex.confidence_pct, 0)}%`} />
        </dl>
        {signals.length > 0 && (
          <div className="mt-4">
            <div className="eyebrow mb-1">Contributing signals · weights sum to 100%</div>
            {signals.map((sig, i) => (
              <SignalBar
                key={`${sig.source_id}-${sig.metric}-${i}`}
                label={`${sig.source_id} · ${sig.metric}`}
                detail={`${fmtNum(sig.value)} vs ${fmtNum(sig.baseline)} · z ${fmtNum(sig.z_score, 2)}`}
                weightPct={sig.weight_pct}
              />
            ))}
          </div>
        )}
      </section>

      <section className="border-b border-line px-5 py-4" aria-labelledby="reason-h">
        <h3 id="reason-h" className="eyebrow">
          04 · Merged reasoning · {incident.merged_alert_count ?? 1} correlated alert
          {(incident.merged_alert_count ?? 1) === 1 ? '' : 's'}
        </h3>
        {steps.length > 0 && (
          <ol className="mt-3 space-y-1.5">
            {steps.map((s, i) => (
              <li key={i} className="flex gap-3 text-meta">
                <span className="num w-4 shrink-0 text-right text-subtle">{i + 1}</span>
                <span className="num min-w-0 break-words text-fg">{s}</span>
              </li>
            ))}
          </ol>
        )}
        {merges.length > 0 && (
          <div className="mt-4">
            <div className="eyebrow mb-1">Merge timeline · 45 s wall-clock window</div>
            <MergeTimeline merges={merges} tzMode={tzMode} />
          </div>
        )}
        {steps.length === 0 && merges.length === 0 && (
          <p className="mt-2 text-meta text-subtle">No reasoning path recorded.</p>
        )}
      </section>
    </article>
  )
}

function QueueSkeleton() {
  return (
    <ul aria-hidden="true">
      {Array.from({ length: 5 }, (_, i) => (
        <li key={i} className="border-b border-line px-4 py-3">
          <Skeleton className="h-3 w-32" />
          <Skeleton className="mt-2 h-4 w-24" />
          <Skeleton className="mt-2 h-3 w-40" />
        </li>
      ))}
    </ul>
  )
}

export default function IncidentWorkbench({
  incidents,
  loading,
  jwt,
  onUpdated,
  onError,
  tzMode,
  now,
  onOpenDrills,
  renderEgress,
}) {
  const [filter, setFilter] = useState('needs')
  const [selectedId, setSelectedId] = useState(null)
  const [expanded, setExpanded] = useState(false)

  const counts = useMemo(
    () => ({
      needs: incidents.filter((i) => matchesFilter(i, 'needs')).length,
      OPEN: incidents.filter((i) => matchesFilter(i, 'OPEN')).length,
      all: incidents.length,
    }),
    [incidents],
  )

  // Default to "Needs approval" only while something needs approval.
  const effectiveFilter = filter === 'needs' && counts.needs === 0 ? 'all' : filter
  const visible = useMemo(
    () => incidents.filter((i) => matchesFilter(i, effectiveFilter)),
    [incidents, effectiveFilter],
  )
  const selected =
    incidents.find((i) => i.incident_id === selectedId) || visible[0] || null

  return (
    <section
      aria-labelledby="queue-h"
      className="overflow-hidden rounded-md border border-line bg-surface shadow-1"
    >
      <SectionHeader
        id="queue-h"
        title="Incidents"
        meta={`${counts.OPEN} open · ${counts.needs} awaiting approval`}
        right={
          <div role="tablist" aria-label="Filter incidents" className="flex gap-1">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                type="button"
                role="tab"
                aria-selected={effectiveFilter === f.id}
                onClick={() => {
                  setFilter(f.id)
                  setExpanded(false)
                }}
                className={`min-h-8 rounded-sm px-2.5 text-meta font-medium transition-colors duration-150 ${
                  effectiveFilter === f.id
                    ? 'bg-raised text-head'
                    : 'text-subtle hover:bg-hover hover:text-fg'
                }`}
              >
                {f.label}
                <span className="num ml-1.5 text-subtle">{counts[f.id]}</span>
              </button>
            ))}
          </div>
        }
      />
      <div className="grid lg:grid-cols-[minmax(260px,320px)_1fr]">
        <div className="max-h-[420px] overflow-y-auto border-b border-line lg:max-h-[calc(100vh-15rem)] lg:min-h-[420px] lg:border-b-0 lg:border-r">
          {loading ? (
            <QueueSkeleton />
          ) : visible.length === 0 ? (
            <EmptyState
              title={incidents.length ? 'Nothing in this view' : 'No incidents yet'}
              action={
                incidents.length ? (
                  <Button onClick={() => setFilter('all')}>Show all incidents</Button>
                ) : (
                  <Button variant="primary" onClick={onOpenDrills}>
                    Run a chaos drill
                  </Button>
                )
              }
            >
              {incidents.length
                ? 'Try another filter.'
                : 'Box 2 has not raised an incident for this tenant. Fire a drill to see detection, merging and remediation end to end.'}
            </EmptyState>
          ) : (
            <>
              <ul aria-label="Incident queue">
                {(expanded ? visible : visible.slice(0, QUEUE_CAP)).map((inc) => (
                  <QueueRow
                    key={inc.incident_id}
                    inc={inc}
                    selected={selected?.incident_id === inc.incident_id}
                    onSelect={setSelectedId}
                    now={now}
                  />
                ))}
              </ul>
              {visible.length > QUEUE_CAP && !expanded && (
                <div className="border-t border-line px-4 py-2.5 text-center">
                  <Button variant="ghost" onClick={() => setExpanded(true)}>
                    Show all {visible.length} incidents
                  </Button>
                </div>
              )}
            </>
          )}
        </div>
        <div className="min-w-0 lg:max-h-[calc(100vh-15rem)] lg:overflow-y-auto">
          {loading ? (
            <div className="space-y-3 p-5" aria-hidden="true">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-24 w-full" />
            </div>
          ) : selected ? (
            <Detail
              incident={selected}
              jwt={jwt}
              onUpdated={onUpdated}
              onError={onError}
              tzMode={tzMode}
              egressSlot={renderEgress(selected)}
            />
          ) : (
            <EmptyState title="Select an incident">
              Its merged reasoning, the egress proof and the pending remediation appear here.
            </EmptyState>
          )}
        </div>
      </div>
    </section>
  )
}
