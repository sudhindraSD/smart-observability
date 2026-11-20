import { useMemo } from 'react'
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Badge, EmptyNote, HealthBadge, Panel } from './ui.jsx'
import { fmtAgo, fmtClock, fmtNum } from '../timefmt.js'

function parseJsonMaybe(value) {
  if (value === null || value === undefined) return {}
  if (typeof value === 'object') return value
  try {
    return JSON.parse(value)
  } catch {
    return {}
  }
}

const CHART_SETS = [
  {
    title: 'Infrastructure',
    note: 'cpu / memory / disk %',
    fields: [
      ['cpu_pct', '#38e8c8'],
      ['memory_pct', '#818cf8'],
      ['disk_pct', '#fbbf24'],
    ],
  },
  {
    title: 'Network',
    note: 'latency ms / packet loss %',
    fields: [
      ['latency_ms', '#f472b6'],
      ['packet_loss_pct', '#fb923c'],
    ],
  },
  {
    title: 'Security',
    note: 'failed logins / 1m',
    fields: [['failed_logins_1m', '#f87171']],
  },
]

// Rows are strictly ordered by event_time_utc (T0) — the chart X axis plots T0,
// labelled in UTC or the source timezone per the header toggle.
function buildRows(events, tzMode) {
  return [...events]
    .sort((a, b) => Date.parse(a.event_time_utc) - Date.parse(b.event_time_utc))
    .map((e) => {
      const m = parseJsonMaybe(e.metrics_json)
      const s = parseJsonMaybe(e.security_json)
      return {
        label: fmtClock(e.event_time_utc, tzMode, e.source_timezone),
        cpu_pct: m.cpu_pct ?? null,
        memory_pct: m.memory_pct ?? null,
        disk_pct: m.disk_pct ?? null,
        latency_ms: m.latency_ms ?? null,
        packet_loss_pct: m.packet_loss_pct ?? null,
        failed_logins_1m: s.failed_logins_1m ?? null,
      }
    })
}

function SeriesChart({ title, note, fields, rows, tzLabel }) {
  return (
    <div className="rounded-xl bg-panel-2/40 p-3 ring-1 ring-[var(--color-edge)]">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[11px] font-bold uppercase tracking-wider text-slate-300">
          {title}
        </span>
        <span className="text-[9.5px] text-slate-500">{note}</span>
      </div>
      <div className="mt-1 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={rows}
            syncId="source-series"
            margin={{ top: 6, right: 10, bottom: 0, left: -18 }}
          >
            <CartesianGrid stroke="#1c2536" strokeDasharray="3 3" vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: '#64748b', fontSize: 10 }}
              stroke="#1c2536"
              minTickGap={30}
            />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} stroke="#1c2536" width={52} />
            <Tooltip
              contentStyle={{
                background: '#0b101b',
                border: '1px solid #1c2536',
                borderRadius: 8,
                fontSize: 11,
              }}
              labelStyle={{ color: '#94a3b8' }}
            />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            {fields.map(([key, color]) => (
              <Line
                key={key}
                type="monotone"
                dataKey={key}
                stroke={color}
                strokeWidth={1.8}
                dot={false}
                isAnimationActive={false}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-1 text-right text-[9.5px] text-slate-500">
        x = event_time_utc (T0) · {tzLabel}
      </div>
    </div>
  )
}

// Panel D: pseudonymized source cards + synchronized event-time charts.
export default function SourcesPanel({ sources, seriesMap, selectedSource, onSelect, tzMode }) {
  const events = selectedSource ? seriesMap[selectedSource] || [] : []
  const rows = useMemo(() => buildRows(events, tzMode), [events, tzMode])
  const sourceTz = events.length ? events[events.length - 1].source_timezone || 'UTC' : 'UTC'
  const tzLabel = tzMode === 'UTC' ? 'UTC' : sourceTz

  return (
    <Panel
      title="Monitored Sources"
      subtitle="pseudonymized identities only · click a card for its event-time series"
      className="mt-3"
    >
      {sources.length === 0 ? (
        <EmptyNote>No sources registered for this tenant yet.</EmptyNote>
      ) : (
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
          {sources.map((src) => {
            const m = parseJsonMaybe(src.latest_metrics_json)
            const s = parseJsonMaybe(src.latest_security_json)
            const selected = src.source_id === selectedSource
            return (
              <button
                key={src.source_id}
                type="button"
                onClick={() => onSelect(src.source_id)}
                className={`rounded-xl p-3 text-left ring-1 transition ${
                  selected
                    ? 'bg-accent/5 ring-accent/70'
                    : 'bg-panel-2/50 ring-[var(--color-edge)] hover:bg-panel-2/80'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="num text-[13px] font-semibold text-slate-100">
                    {src.source_id}
                  </span>
                  <HealthBadge state={src.health_state} />
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  <Badge>{src.source_type}</Badge>
                  <Badge>
                    {src.upstream_source_id ? `↑ ${src.upstream_source_id}` : 'edge source'}
                  </Badge>
                  <Badge tone="bg-accent/10 text-accent ring-accent/40">
                    secrets scrubbed: {src.secrets_scrubbed_total ?? 0}
                  </Badge>
                </div>
                <div className="mt-2 grid grid-cols-3 gap-x-2 gap-y-1 text-[10.5px]">
                  {[
                    ['CPU', `${fmtNum(m.cpu_pct)}%`],
                    ['Mem', `${fmtNum(m.memory_pct)}%`],
                    ['Disk', `${fmtNum(m.disk_pct)}%`],
                    ['Latency', `${fmtNum(m.latency_ms)} ms`],
                    ['Loss', `${fmtNum(m.packet_loss_pct)}%`],
                    ['Logins×1m', String(s.failed_logins_1m ?? '—')],
                  ].map(([k, v]) => (
                    <div key={k}>
                      <span className="block text-[8.5px] font-bold uppercase tracking-wider text-slate-500">
                        {k}
                      </span>
                      <span className="num block text-slate-200">{v}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-1.5 text-[9.5px] text-slate-500">
                  last ingested {fmtAgo(src.last_ingested_utc)}
                </div>
              </button>
            )
          })}
        </div>
      )}

      <div className="mt-4">
        {!selectedSource ? (
          <EmptyNote>Select a source card to load its event-time series.</EmptyNote>
        ) : rows.length === 0 ? (
          <EmptyNote>Loading series for {selectedSource}…</EmptyNote>
        ) : (
          <>
            <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
              <h3 className="num text-[12px] font-bold text-slate-200">
                Event-Time Series — {selectedSource}
              </h3>
              <span className="text-[10px] text-slate-500">
                {rows.length} points · live WS frames appended in T0 order
              </span>
            </div>
            <div className="grid gap-3 lg:grid-cols-3">
              {CHART_SETS.map((set) => (
                <SeriesChart
                  key={set.title}
                  title={set.title}
                  note={set.note}
                  fields={set.fields}
                  rows={rows}
                  tzLabel={tzLabel}
                />
              ))}
            </div>
          </>
        )}
      </div>
    </Panel>
  )
}
