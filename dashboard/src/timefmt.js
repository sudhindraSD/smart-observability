// Time formatting helpers. Chart axes and timestamps render either in UTC or
// in the source's own timezone (source_timezone from the telemetry rows).

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

function partsIn(date, timeZone) {
  const fmt = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    hour12: false,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
  const out = {}
  for (const p of fmt.formatToParts(date)) {
    if (p.type !== 'literal') out[p.type] = p.value
  }
  return out
}

export function fmtClock(iso, tzMode = 'UTC', sourceTz = 'UTC') {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  const tz = tzMode === 'source' ? sourceTz : 'UTC'
  const p = partsIn(d, tz)
  return `${p.hour}:${p.minute}:${p.second}`
}

export function fmtStamp(iso, tzMode = 'UTC', sourceTz = 'UTC') {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return String(iso)
  const tz = tzMode === 'source' ? sourceTz : 'UTC'
  const p = partsIn(d, tz)
  return `${d.getUTCFullYear()}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second} ${tz === 'UTC' ? 'UTC' : tz.split('/')[1] || tz}`
}

export function relSeconds(iso, nowMs = Date.now()) {
  if (!iso) return null
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return null
  return Math.max(0, Math.round((nowMs - t) / 1000))
}

export function fmtAgo(iso, nowMs = Date.now()) {
  const s = relSeconds(iso, nowMs)
  if (s === null) return '—'
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s ago`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ago`
}

export function fmtNum(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return '—'
  const n = Number(value)
  if (Number.isInteger(n)) return String(n)
  return n.toFixed(digits)
}

export function pct95(sortedValues) {
  const n = sortedValues.length
  if (n === 0) return null
  const idx = Math.min(n - 1, Math.max(0, Math.ceil(0.95 * n) - 1))
  return sortedValues[idx]
}

// InternalRawEvent-compatible timestamp (shared/contracts.py utc_now_iso style).
export function utcIsoNow(offsetMs = 0) {
  return new Date(Date.now() + offsetMs).toISOString()
}
