// Automated tests for the time/percentile helpers (timefmt.js), including the
// p95 window used by the browser-side T5 latency measurement.
// Run with: node --test src/timefmt.test.js  (from dashboard/)

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fmtClock, fmtStamp, relSeconds, fmtAgo, fmtNum, pct95, utcIsoNow } from './timefmt.js'

const ISO = '2026-01-15T20:30:00Z' // 20:30 UTC == 02:00 next day in Asia/Kolkata (+5:30)

test('fmtClock renders HH:MM:SS in UTC or the source timezone', () => {
  assert.equal(fmtClock(ISO, 'UTC'), '20:30:00')
  assert.equal(fmtClock(ISO, 'source', 'Asia/Kolkata'), '02:00:00')
})

test('fmtStamp renders the full timestamp with the zone suffix', () => {
  assert.equal(fmtStamp(ISO, 'UTC'), '2026-01-15 20:30:00 UTC')
  assert.equal(fmtStamp(ISO, 'source', 'Asia/Kolkata'), '2026-01-16 02:00:00 Kolkata')
})

test('empty and malformed timestamps degrade gracefully', () => {
  assert.equal(fmtClock(null), '—')
  assert.equal(fmtClock(''), '—')
  assert.equal(fmtClock('not-a-date'), 'not-a-date')
  assert.equal(fmtStamp(undefined), '—')
})

test('relSeconds clamps future timestamps to 0 and rejects garbage', () => {
  const now = Date.now()
  assert.equal(relSeconds(new Date(now - 30_000).toISOString(), now), 30)
  assert.equal(relSeconds(new Date(now + 60_000).toISOString(), now), 0)
  assert.equal(relSeconds('garbage', now), null)
  assert.equal(relSeconds('', now), null)
})

test('fmtAgo buckets seconds, minutes and hours', () => {
  const now = Date.now()
  assert.equal(fmtAgo(new Date(now - 45_000).toISOString(), now), '45s ago')
  assert.equal(fmtAgo(new Date(now - 125_000).toISOString(), now), '2m 5s ago')
  assert.equal(fmtAgo(new Date(now - 7_200_000).toISOString(), now), '2h 0m ago')
  assert.equal(fmtAgo(null, now), '—')
})

test('fmtNum formats floats and dashes out nulls/NaN', () => {
  assert.equal(fmtNum(34.25), '34.3')
  assert.equal(fmtNum(34.25, 2), '34.25')
  assert.equal(fmtNum(34), '34')
  assert.equal(fmtNum(null), '—')
  assert.equal(fmtNum('oops'), '—')
})

test('pct95 picks the 95th percentile of a sorted rolling window', () => {
  assert.equal(pct95([]), null)
  assert.equal(pct95([4.2]), 4.2)
  assert.equal(pct95(Array.from({ length: 100 }, (_, i) => i + 1)), 95)
  assert.equal(pct95([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]), 10)
})

test('utcIsoNow emits ISO timestamps with an optional offset', () => {
  const before = Date.now()
  const stamp = utcIsoNow()
  const future = utcIsoNow(1500)
  assert.ok(!Number.isNaN(Date.parse(stamp)))
  assert.ok(Date.parse(stamp) >= before - 5)
  assert.ok(Date.parse(future) - before >= 1400 && Date.parse(future) - before <= 1600)
})
