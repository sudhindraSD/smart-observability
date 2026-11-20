// Automated tests for the browser-side chaos engine (chaos.js).
// Verifies that bank-a live-mode synthesis emits payloads matching
// shared/contracts.InternalRawEvent verbatim, and that hospital-b rides the
// mock stream. Run with: node --test src/chaos.test.js  (from dashboard/)

import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { fireChaos, resetLiveIdentities, rememberLiveIdentities } from './chaos.js'
import { SECRET_LOG_LINE } from './constants.js'

const SERVER_RAW = {
  source_type: 'server',
  source_timezone: 'Asia/Kolkata',
  real_hostname: 'prod-db-01',
  real_ip: '10.20.4.15',
  upstream_device_real_name: 'edge-rtr-01',
}

const NET_RAW = {
  source_type: 'network_device',
  source_timezone: 'Asia/Kolkata',
  real_hostname: 'edge-rtr-01',
  real_ip: '10.20.4.1',
}

const LIVE = { tenantId: 'bank-a', proxy: '/col-a', liveMode: true }

let calls
let proofRows
let originalFetch

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeEach(() => {
  originalFetch = globalThis.fetch
  calls = []
  proofRows = [{ raw: { ...SERVER_RAW } }, { raw: { ...NET_RAW } }]
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options })
    if (String(url).includes('/api/egress-proof')) {
      return jsonResponse({ rows: proofRows })
    }
    return jsonResponse({ accepted: true })
  }
})

afterEach(() => {
  globalThis.fetch = originalFetch
})

function posted() {
  return calls
    .filter((c) => c.url.endsWith('/api/ingest-raw'))
    .map((c) => JSON.parse(c.options.body))
}

test('mock mode rides POST /chaos/{scenario}?site={tenant}', async () => {
  const line = await fireChaos('cpu_anomaly', {
    tenantId: 'hospital-b',
    proxy: '/col-b',
    liveMode: false,
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/chaos/cpu_anomaly?site=hospital-b')
  assert.equal(calls[0].options.method, 'POST')
  assert.match(line, /mock stream injected "cpu_anomaly" for hospital-b/)
})

test('secret injects one live event carrying the secret-bearing raw_log_line', async () => {
  const line = await fireChaos('secret', LIVE)
  const events = posted()
  assert.equal(events.length, 1)
  assert.equal(events[0].raw_log_line, SECRET_LOG_LINE)
  assert.match(SECRET_LOG_LINE, /Authorization: Bearer/)
  assert.match(line, /prod-db-01/)
})

test('synthesized events match the frozen InternalRawEvent field set verbatim', async () => {
  await fireChaos('secret', LIVE)
  const [ev] = posted()
  assert.deepEqual(Object.keys(ev).sort(), [
    'event_time_utc',
    'metrics',
    'raw_log_line',
    'real_hostname',
    'real_ip',
    'source_timezone',
    'source_type',
    'upstream_device_real_name',
  ])
  assert.equal(ev.source_type, 'server')
  assert.equal(ev.real_hostname, 'prod-db-01')
  assert.equal(ev.upstream_device_real_name, 'edge-rtr-01')
  assert.ok(!Number.isNaN(Date.parse(ev.event_time_utc)))
  assert.deepEqual(Object.keys(ev.metrics).sort(), ['cpu_pct', 'disk_pct', 'memory_pct', 'service_up'])
})

test('failed_logins posts exactly 14 failed-login events', async () => {
  const line = await fireChaos('failed_logins', LIVE)
  const events = posted()
  assert.equal(events.length, 14)
  for (const ev of events) {
    assert.equal(ev.failed_login_event, true)
    assert.match(ev.raw_log_line, /^Failed password for invalid user oracle/)
  }
  assert.match(line, /14 failed-login events/)
})

test('latency_spike degrades the router with 185 ms / 4.2% loss', async () => {
  await fireChaos('latency_spike', LIVE)
  const [ev] = posted()
  assert.equal(ev.source_type, 'network_device')
  assert.equal(ev.metrics.latency_ms, 185.0)
  assert.equal(ev.metrics.packet_loss_pct, 4.2)
  assert.equal(ev.metrics.connectivity, 'degraded')
})

test('cpu_anomaly pushes CPU and memory past the breach ceiling', async () => {
  await fireChaos('cpu_anomaly', LIVE)
  const [ev] = posted()
  assert.equal(ev.metrics.cpu_pct, 92.0)
  assert.equal(ev.metrics.memory_pct, 88.4)
})

test('cascade fires router + 2 downstream posts spaced 1.5s apart', async () => {
  const started = Date.now()
  const line = await fireChaos('cascade_incident', LIVE)
  const events = posted()
  assert.equal(events.length, 3)
  assert.equal(events[0].source_type, 'network_device')
  assert.equal(events[0].metrics.connectivity, 'degraded')
  assert.equal(events[1].source_type, 'server')
  assert.equal(events[2].source_type, 'server')
  const t2 = Date.parse(events[1].event_time_utc)
  const t3 = Date.parse(events[2].event_time_utc)
  assert.ok(t3 - t2 >= 1200 && t3 - t2 <= 1800, `event_time spacing ${t3 - t2}ms`)
  assert.ok(Date.now() - started >= 2900, 'wall-clock spacing between posts missing')
  assert.match(line, /router \+ 2 downstream posts 1\.5s apart/)
})

test('cascade works from server-only telemetry: router derived from upstream_device_real_name', async () => {
  resetLiveIdentities()
  proofRows = [{ raw: { ...SERVER_RAW } }]
  const line = await fireChaos('cascade_incident', LIVE)
  const events = posted()
  assert.equal(events.length, 3)
  assert.equal(events[0].source_type, 'network_device')
  assert.equal(events[0].real_hostname, 'edge-rtr-01')
  assert.equal(events[0].metrics.connectivity, 'degraded')
  assert.equal(events[1].source_type, 'server')
  assert.equal(events[2].source_type, 'server')
  const t1 = Date.parse(events[0].event_time_utc)
  const t2 = Date.parse(events[1].event_time_utc)
  const t3 = Date.parse(events[2].event_time_utc)
  assert.ok(t2 - t1 >= 1200 && t2 - t1 <= 1800, `router->down1 spacing ${t2 - t1}ms`)
  assert.ok(t3 - t2 >= 1200 && t3 - t2 <= 1800, `down1->down2 spacing ${t3 - t2}ms`)
  assert.match(line, /router \+ 2 downstream posts 1\.5s apart/)
})

test('duplicate_payload posts the same forced_payload_id twice', async () => {
  const line = await fireChaos('duplicate_payload', LIVE)
  const events = posted()
  assert.equal(events.length, 2)
  assert.ok(events[0].forced_payload_id.startsWith('forced-dup-'))
  assert.equal(events[0].forced_payload_id, events[1].forced_payload_id)
  assert.equal(JSON.stringify(events[0]), JSON.stringify(events[1]))
  assert.match(line, /Box 2 will block the replay/)
})

test('out_of_order stamps event_time_utc 90 seconds in the past', async () => {
  await fireChaos('out_of_order', LIVE)
  const [ev] = posted()
  const ageSeconds = (Date.now() - Date.parse(ev.event_time_utc)) / 1000
  assert.ok(ageSeconds >= 89 && ageSeconds <= 91, `age ${ageSeconds}s`)
})

test('unknown scenario is rejected', async () => {
  await assert.rejects(fireChaos('meteor_strike', LIVE), /unknown scenario meteor_strike/)
})

test('live mode refuses to fire before any host telemetry has egressed', async () => {
  resetLiveIdentities()
  proofRows = []
  await assert.rejects(fireChaos('secret', LIVE), /no live host telemetry yet/)
})

test('supplied egress rows skip discovery: the ingest POST is the very first call', async () => {
  const line = await fireChaos('secret', {
    ...LIVE,
    egressRows: [{ raw: { ...SERVER_RAW } }, { raw: { ...NET_RAW } }],
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  assert.equal(ev.real_hostname, 'prod-db-01')
  assert.equal(ev.raw_log_line, SECRET_LOG_LINE)
  assert.match(line, /prod-db-01/)
})

test('supplied raw identities (serverRaw/netRaw) skip discovery too', async () => {
  await fireChaos('cpu_anomaly', { ...LIVE, serverRaw: { ...SERVER_RAW }, netRaw: { ...NET_RAW } })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  assert.equal(ev.metrics.cpu_pct, 92.0)
  assert.equal(ev.metrics.memory_pct, 88.4)
})

test('supplied identity bundle {server, net} is honored verbatim', async () => {
  await fireChaos('latency_spike', {
    ...LIVE,
    identities: { server: { ...SERVER_RAW }, net: { ...NET_RAW } },
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  assert.equal(ev.source_type, 'network_device')
  assert.equal(ev.metrics.latency_ms, 185.0)
})

test('without supplied identities the discovery GET still precedes the POST', async () => {
  resetLiveIdentities()
  await fireChaos('secret', LIVE)
  assert.equal(calls.length, 2)
  assert.equal(calls[0].url, '/col-a/api/egress-proof?limit=200')
  assert.equal(calls[1].url, '/col-a/api/ingest-raw')
})

test('a second drill reuses the remembered identities and skips discovery', async () => {
  resetLiveIdentities()
  await fireChaos('secret', LIVE)
  assert.equal(calls.length, 2)
  calls.length = 0
  const line = await fireChaos('cpu_anomaly', LIVE)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  assert.match(line, /prod-db-01/)
})

test('deeply nested supplied telemetry is found without any discovery call', async () => {
  const line = await fireChaos('secret', {
    ...LIVE,
    snapshot: {
      latest: {
        frames: [{ raw: { ...SERVER_RAW } }, { raw: { ...NET_RAW } }],
      },
    },
  })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  assert.equal(ev.real_hostname, 'prod-db-01')
  assert.equal(ev.raw_log_line, SECRET_LOG_LINE)
  assert.match(line, /prod-db-01/)
})

test('supplier functions and promises are resolved before any network call', async () => {
  const rows = () => [{ raw: { ...SERVER_RAW } }, { raw: { ...NET_RAW } }]
  await fireChaos('secret', { ...LIVE, liveTelemetry: rows })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')

  calls.length = 0
  await fireChaos('out_of_order', { ...LIVE, proof: Promise.resolve({ rows: rows() }) })
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  const ageSeconds = (Date.now() - Date.parse(ev.event_time_utc)) / 1000
  assert.ok(ageSeconds >= 89 && ageSeconds <= 91, `age ${ageSeconds}s`)
})

test('rememberLiveIdentities seeds the cache so the first drill POSTs straight away', async () => {
  resetLiveIdentities()
  assert.ok(rememberLiveIdentities([{ raw: { ...SERVER_RAW } }, { raw: { ...NET_RAW } }]))
  await fireChaos('latency_spike', LIVE)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].url, '/col-a/api/ingest-raw')
  const [ev] = posted()
  assert.equal(ev.source_type, 'network_device')
})
