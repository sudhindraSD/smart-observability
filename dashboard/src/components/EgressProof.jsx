import { useCallback, useEffect, useMemo, useState } from 'react'
import { Lock, RefreshCw } from 'lucide-react'
import { api } from '../api.js'
import { fmtStamp } from '../timefmt.js'
import { Button, Skeleton, Status, Tag } from './ui.jsx'

const RAW_KEYS = ['real_hostname', 'real_ip', 'upstream_device_real_name', 'raw_log_line']
const EGRESS_KEYS = [
  'source_id',
  'upstream_source_id',
  'event_category',
  'severity',
  'local_health_hint',
  'alert_context',
]

function show(v) {
  if (v === null || v === undefined || v === '') return '∅'
  return String(v)
}

// Box 1 egress audit for the incident's sources, read from the collector's own
// /api/egress-proof. Left: identifying fields that never leave Box 1. Right:
// the redacted payload Box 2 actually received, with its recorded SHA-256.
export default function EgressProof({ proxy, sourceIds, tzMode }) {
  const [rows, setRows] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const fetchRows = useCallback(async () => {
    try {
      const res = await api.egressProof(proxy, 200)
      setRows(res.rows || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [proxy])

  const load = useCallback(() => {
    setLoading(true)
    return fetchRows()
  }, [fetchRows])

  useEffect(() => {
    const first = setTimeout(fetchRows, 0)
    const id = setInterval(fetchRows, 10000)
    return () => {
      clearTimeout(first)
      clearInterval(id)
    }
  }, [fetchRows])

  const match = useMemo(() => {
    if (!rows) return null
    const ids = new Set(sourceIds)
    return (
      rows.find((r) => r.egress && ids.has(r.egress.source_id) && r.egress.redaction_audit?.secrets_scrubbed_count > 0) ||
      rows.find((r) => r.egress && ids.has(r.egress.source_id)) ||
      null
    )
  }, [rows, sourceIds])

  return (
    <section className="border-b border-line px-5 py-4" aria-labelledby="egress-h">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="egress-h" className="eyebrow flex items-center gap-1.5">
          <Lock size={13} aria-hidden="true" /> 01 · Egress proof · Box 1 audit log
        </h3>
        <Button variant="ghost" onClick={load} disabled={loading} aria-label="Refresh egress proof">
          <RefreshCw size={14} aria-hidden="true" className={loading ? 'motion-safe:animate-spin' : ''} />
          Refresh
        </Button>
      </div>

      {error && !rows ? (
        <div className="mt-3 rounded-md border border-crit/40 p-3 text-meta">
          <p className="text-crit">Collector audit log unreachable at {proxy}.</p>
          <p className="mt-1 text-subtle">{error}</p>
          <Button className="mt-3" onClick={load}>
            Retry
          </Button>
        </div>
      ) : rows === null ? (
        <div className="mt-3 grid gap-3 md:grid-cols-2" aria-hidden="true">
          <Skeleton className="h-36" />
          <Skeleton className="h-36" />
        </div>
      ) : !match ? (
        <p className="mt-3 text-meta text-subtle">
          None of the last {rows.length} sent payloads came from {sourceIds.join(', ')}. The
          audit log keeps the newest rows, so older incidents may have rotated out.
        </p>
      ) : (
        <ProofBody row={match} tzMode={tzMode} />
      )}
    </section>
  )
}

function ProofBody({ row, tzMode }) {
  const raw = row.raw || {}
  const eg = row.egress || {}
  const audit = eg.redaction_audit || {}
  const dropped = audit.raw_fields_dropped || []
  return (
    <div className="mt-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-meta">
        <Status tone="ok">{row.status}</Status>
        <span className="num text-subtle">sent {fmtStamp(row.egress_sent_utc, tzMode, eg.source_timezone)}</span>
        {row.is_backlog_replay && <Tag>backlog replay</Tag>}
        <span className="num text-subtle">payload {row.payload_id}</span>
      </div>

      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <div className="rounded-md border border-line bg-canvas p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="eyebrow">Stays in Box 1</span>
            <span className="text-label text-subtle">raw event</span>
          </div>
          <dl className="mt-2 space-y-1.5">
            {RAW_KEYS.map((k) => (
              <div key={k} className="grid grid-cols-[minmax(0,9rem)_1fr] gap-2 text-meta">
                <dt className="num truncate text-subtle">{k}</dt>
                <dd className="num min-w-0 break-all text-warn">{show(raw[k])}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div className="rounded-md border border-line bg-canvas p-3">
          <div className="flex items-center justify-between gap-2">
            <span className="eyebrow">Crossed to Box 2</span>
            <span className="text-label text-subtle">redacted payload</span>
          </div>
          <dl className="mt-2 space-y-1.5">
            {[
              ...EGRESS_KEYS.map((k) => [k, eg[k]]),
              ['security_risk', eg.security_summary?.security_risk],
              [
                'metrics',
                Object.entries(eg.metrics || {})
                  .filter(([, v]) => v !== null && v !== undefined)
                  .map(([m, v]) => `${m}=${typeof v === 'number' ? Number(v.toFixed(2)) : v}`)
                  .join(' '),
              ],
            ].map(([k, v]) => (
              <div key={k} className="grid grid-cols-[minmax(0,9rem)_1fr] gap-2 text-meta">
                <dt className="num truncate text-subtle">{k}</dt>
                <dd className="num min-w-0 break-words text-fg">{show(v)}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>

      <dl className="mt-3 grid gap-3 sm:grid-cols-3">
        <div>
          <dt className="eyebrow">Fields dropped</dt>
          <dd className="mt-1 flex flex-wrap gap-1">
            {dropped.length ? dropped.map((f) => <Tag key={f} className="num">{f}</Tag>) : <span className="text-meta text-subtle">none</span>}
          </dd>
        </div>
        <div>
          <dt className="eyebrow">Secrets scrubbed</dt>
          <dd className="num mt-1 text-meta text-fg">
            {audit.secrets_scrubbed_count ?? 0}
            {(audit.secret_types_detected || []).length > 0 && (
              <span className="text-subtle"> · {audit.secret_types_detected.join(', ')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt className="eyebrow">Pseudonymized</dt>
          <dd className="mt-1 text-meta text-fg">{audit.pseudonymized ? 'Yes' : 'No'}</dd>
        </div>
      </dl>

      <div className="mt-3">
        <div className="eyebrow">SHA-256 of wire bytes · recorded before POST</div>
        <code className="num mt-1 block break-all rounded-sm border border-line bg-canvas px-2 py-1.5 text-meta text-accent-fg">
          {row.payload_sha256}
        </code>
      </div>
    </div>
  )
}
