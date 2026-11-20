// Automated tests for the dashboard's Box 2 API client (api.js).
// Run with: node --test src/api.test.js  (from dashboard/, Node >= 22)

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { api } from './api.js'

let calls
let originalFetch

function jsonResponse(body, { status = 200, statusText = 'OK' } = {}) {
  return new Response(JSON.stringify(body), {
    status,
    statusText,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  originalFetch = globalThis.fetch
  calls = []
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options })
    if (String(url).endsWith('/api/v1/auth/login')) {
      return jsonResponse({ access_token: 'jwt-1', token_type: 'bearer' })
    }
    return jsonResponse({})
  }
})

afterEach(() => {
  globalThis.fetch = originalFetch
})

test('login posts JSON credentials to /api/v1/auth/login', async () => {
  const res = await api.login('bank-a', 'demo123')
  assert.equal(res.access_token, 'jwt-1')
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/api/v1/auth/login')
  assert.equal(calls[0].options.method, 'POST')
  assert.deepEqual(JSON.parse(calls[0].options.body), { username: 'bank-a', password: 'demo123' })
  assert.equal(calls[0].options.headers['Content-Type'], 'application/json')
})

test('authenticated GETs ride the /api proxy with a Bearer JWT', async () => {
  await api.overview('jwt-1')
  await api.slaMetrics('jwt-1')
  await api.incidents('jwt-1')
  assert.deepEqual(
    calls.map((c) => c.url),
    ['/api/v1/overview', '/api/v1/sla-metrics', '/api/v1/incidents'],
  )
  for (const c of calls) {
    assert.equal(c.options.headers.Authorization, 'Bearer jwt-1')
    assert.equal(c.options.method, undefined)
  }
})

test('sourceSeries encodes the source id and honours the limit', async () => {
  await api.sourceSeries('jwt-1', 'srv-01')
  await api.sourceSeries('jwt-1', 'net-abc/x', 50)
  assert.equal(calls[0].url, '/api/v1/sources/srv-01/series?limit=120')
  assert.equal(calls[1].url, `/api/v1/sources/${encodeURIComponent('net-abc/x')}/series?limit=50`)
})

test('thresholds read and write hit GET/PUT /api/v1/thresholds', async () => {
  const config = { cpu_fair_ceiling: 80.0, stale_source_seconds: 35 }
  await api.thresholds('jwt-1')
  await api.putThresholds('jwt-1', config)
  assert.equal(calls[0].url, '/api/v1/thresholds')
  assert.equal(calls[1].options.method, 'PUT')
  assert.deepEqual(JSON.parse(calls[1].options.body), config)
})

test('remediation approve/rollback POST to the incident sub-resources', async () => {
  await api.approveIncident('jwt-1', 'inc-7')
  await api.rollbackIncident('jwt-1', 'inc-7')
  assert.deepEqual(
    calls.map((c) => `${c.options.method} ${c.url}`),
    ['POST /api/v1/incidents/inc-7/approve', 'POST /api/v1/incidents/inc-7/rollback'],
  )
})

test('transitions default limit is 60', async () => {
  await api.transitions('jwt-1')
  assert.equal(calls[0].url, '/api/v1/transitions?limit=60')
})

test('collector proxies hit /col-a and /col-b status, egress proof and control routes', async () => {
  await api.collectorStatus('/col-a')
  await api.egressProof('/col-b', 5)
  await api.toggleLink('/col-a')
  assert.deepEqual(
    calls.map((c) => c.url),
    ['/col-a/api/status', '/col-b/api/egress-proof?limit=5', '/col-a/control/toggle-link'],
  )
  assert.equal(calls[2].options.method, 'POST')
})

test('ingestRaw posts the InternalRawEvent body verbatim', async () => {
  const raw = {
    event_time_utc: '2026-11-21T10:00:00.000Z',
    source_timezone: 'Asia/Kolkata',
    real_hostname: 'prod-db-01',
    real_ip: '10.20.4.15',
    source_type: 'server',
    metrics: { cpu_pct: 34.2 },
  }
  await api.ingestRaw('/col-a', raw)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  assert.deepEqual(JSON.parse(calls[0].options.body), raw)
})

test('chaos scenarios ride POST /chaos/{scenario}?site={tenant}', async () => {
  await api.chaos('secret', 'hospital-b')
  assert.equal(calls[0].url, '/chaos/secret?site=hospital-b')
  assert.equal(calls[0].options.method, 'POST')
})

test('non-OK JSON bodies surface the FastAPI detail and status', async () => {
  globalThis.fetch = async () =>
    jsonResponse({ detail: 'Incident not found' }, { status: 404, statusText: 'Not Found' })
  await assert.rejects(api.incidents('jwt-1'), (err) => {
    assert.equal(err.message, 'Incident not found')
    assert.equal(err.status, 404)
    return true
  })
})

test('non-OK non-JSON bodies fall back to status + statusText', async () => {
  globalThis.fetch = async () =>
    new Response('gateway exploded', { status: 502, statusText: 'Bad Gateway' })
  await assert.rejects(api.collectorStatus('/col-a'), (err) => {
    assert.equal(err.message, '502 Bad Gateway')
    assert.equal(err.status, 502)
    return true
  })
})
