// Live Chaos & Outage Drill engine.
//
// hospital-b runs on the mock stream, so scenarios ride POST /chaos/{scenario}.
// bank-a runs STREAM_MODE=live against the real host, so each scenario is
// synthesized in the browser as a verbatim shared/contracts.InternalRawEvent
// and POSTed to the collector's /api/ingest-raw, on top of real live telemetry.

import { api } from './api.js'
import { SECRET_LOG_LINE } from './constants.js'
import { utcIsoNow } from './timefmt.js'

const CASCADE_STEP_MS = 1500
const OUT_OF_ORDER_OFFSET_MS = -90_000

async function discoverLiveIdentities(proxy) {
  const proof = await api.egressProof(proxy, 200)
  let server = null
  let net = null
  for (const row of proof.rows || []) {
    const raw = row.raw
    if (!raw) continue
    if (!server && raw.source_type === 'server') server = raw
    if (!net && raw.source_type === 'network_device') net = raw
    if (server && net) break
  }
  if (!server) {
    throw new Error('no live host telemetry yet — wait a few seconds for the collector to egress')
  }
  return { server, net }
}

// Live host identity sourcing for drills.
//
// The console already holds real live host telemetry (the egress-proof rows it
// renders), so a drill must POST immediately instead of paying a discovery
// round-trip on every click. Identities can be handed in anywhere inside the
// caller's context — raw events, row arrays, proof wrappers, suppliers — and
// are remembered across drills; only when nothing is known yet do we ask the
// collector's egress proof.

let knownIdentities = null

export function rememberLiveIdentities(rows) {
  const scan = scanForIdentities(rows)
  if (scan.server) {
    knownIdentities = { server: scan.server, net: scan.net }
    return true
  }
  return false
}

export function resetLiveIdentities() {
  knownIdentities = null
}

const isThenable = (value) =>
  !!value && typeof value === 'object' && typeof value.then === 'function'

// Structural scan: walks the whole value tree (any key name, any nesting,
// unwrapping {raw:...} and entering .rows arrays, invoking supplier functions)
// and returns the first server / network_device raw events it meets, preferring
// ones that carry a real hostname. Thenables are collected for the async pass.
function scanForIdentities(root) {
  let serverHosted = null
  let serverAny = null
  let netHosted = null
  let netAny = null
  const thenables = []
  const seen = new WeakSet()
  let calls = 0

  const note = (raw) => {
    if (!raw || typeof raw !== 'object') return
    const hosted = typeof raw.real_hostname === 'string' && raw.real_hostname.length > 0
    if (raw.source_type === 'server') {
      if (hosted) serverHosted = serverHosted || raw
      serverAny = serverAny || raw
    } else if (raw.source_type === 'network_device') {
      if (hosted) netHosted = netHosted || raw
      netAny = netAny || raw
    }
  }
  const settled = () => serverHosted && netHosted

  const visit = (node, depth) => {
    if (depth > 8 || seen.has(node)) return
    if (Array.isArray(node)) {
      seen.add(node)
      for (const item of node) {
        visit(item, depth + 1)
        if (settled()) return
      }
      return
    }
    if (!node || typeof node !== 'object') return
    seen.add(node)
    if (isThenable(node)) {
      if (thenables.length < 6) thenables.push(node)
      return
    }
    if (node instanceof Map || node instanceof Set) {
      for (const value of node instanceof Map ? node.values() : node) {
        visit(value, depth + 1)
        if (settled()) return
      }
      return
    }
    note(node.raw && typeof node.raw === 'object' ? node.raw : node)
    if (settled()) return
    if (Array.isArray(node.rows)) {
      visit(node.rows, depth + 1)
      if (settled()) return
    }
    for (const key of Object.keys(node)) {
      let value
      try {
        value = node[key]
      } catch {
        continue
      }
      if (typeof value === 'function' && calls < 8) {
        calls += 1
        try {
          value = value()
        } catch {
          continue
        }
      }
      visit(value, depth + 1)
      if (settled()) return
    }
  }

  visit(root, 0)
  return {
    server: serverHosted || serverAny,
    net: netHosted || netAny,
    thenables,
  }
}

async function suppliedIdentities(ctx) {
  if (!ctx || typeof ctx !== 'object') return null
  const scan = scanForIdentities(ctx)
  if (scan.server) return { server: scan.server, net: scan.net }
  for (const thenable of scan.thenables) {
    let value
    try {
      value = await thenable
    } catch {
      continue
    }
    const found = scanForIdentities(value)
    if (found.server) return { server: found.server, net: found.net }
  }
  return null
}

function serverEvent(server, overrides = {}) {
  return {
    event_time_utc: utcIsoNow(),
    source_timezone: server.source_timezone,
    real_hostname: server.real_hostname,
    real_ip: server.real_ip,
    source_type: 'server',
    upstream_device_real_name: server.upstream_device_real_name,
    metrics: {
      cpu_pct: 34.2,
      memory_pct: 61.8,
      disk_pct: 47.5,
      service_up: true,
    },
    ...overrides,
  }
}

function routerEvent(net, server = null, overrides = {}) {
  let identity = net
  if (!identity && server && server.upstream_device_real_name) {
    // Server-only telemetry: the uplink router is named by the frozen
    // InternalRawEvent.upstream_device_real_name field (real_ip is optional).
    identity = {
      source_timezone: server.source_timezone,
      real_hostname: server.upstream_device_real_name,
    }
  }
  if (!identity) {
    throw new Error('no live router telemetry yet — wait a few seconds for the collector to egress')
  }
  return {
    event_time_utc: utcIsoNow(),
    source_timezone: identity.source_timezone,
    real_hostname: identity.real_hostname,
    real_ip: identity.real_ip,
    source_type: 'network_device',
    metrics: {
      bandwidth_mbps: 940.1,
      latency_ms: 12.4,
      packet_loss_pct: 0.0,
      connectivity: 'up',
    },
    ...overrides,
  }
}

async function postAll(proxy, events) {
  for (const ev of events) {
    await api.ingestRaw(proxy, ev)
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// Returns a human-readable result line for the drill log.
export async function fireChaos(scenario, ...args) {
  const ctx = Object.assign({}, ...args.filter((a) => a && typeof a === 'object'))
  const { tenantId, proxy, liveMode } = ctx
  if (!liveMode) {
    await api.chaos(scenario, tenantId)
    return `mock stream injected "${scenario}" for ${tenantId}`
  }

  const supplied = await suppliedIdentities(ctx)
  const { server, net } = supplied || knownIdentities || (await discoverLiveIdentities(proxy))
  knownIdentities = { server, net }
  if (!server) {
    throw new Error('no live host telemetry yet — wait a few seconds for the collector to egress')
  }
  const host = server.real_hostname

  switch (scenario) {
    case 'secret': {
      await postAll(proxy, [
        serverEvent(server, { raw_log_line: SECRET_LOG_LINE }),
      ])
      return `secret-bearing log line injected on live host ${host}`
    }

    case 'failed_logins': {
      const bursts = []
      for (let i = 0; i < 14; i += 1) {
        bursts.push(
          serverEvent(server, {
            raw_log_line: `Failed password for invalid user oracle from 10.20.4.${15 + (i % 200)} port ${47000 + i} ssh2`,
            failed_login_event: true,
          }),
        )
      }
      await postAll(proxy, bursts)
      return `14 failed-login events posted against live host ${host}`
    }

    case 'latency_spike': {
      const router = routerEvent(net, server, {
        metrics: { bandwidth_mbps: 940.1, latency_ms: 185.0, packet_loss_pct: 4.2, connectivity: 'degraded' },
      })
      await postAll(proxy, [router])
      return `latency spike (185 ms / 4.2% loss) injected on ${router.real_hostname}`
    }

    case 'cpu_anomaly': {
      await postAll(proxy, [
        serverEvent(server, {
          metrics: { cpu_pct: 92.0, memory_pct: 88.4, disk_pct: 47.5, service_up: true },
        }),
      ])
      return `CPU/memory anomaly injected on live host ${host}`
    }

    case 'cascade_incident': {
      const router = routerEvent(net, server, {
        metrics: { bandwidth_mbps: 640.0, latency_ms: 165.0, packet_loss_pct: 3.5, connectivity: 'degraded' },
      })
      await postAll(proxy, [router])
      await delay(CASCADE_STEP_MS)
      await postAll(proxy, [
        serverEvent(server, {
          metrics: { cpu_pct: 84.0, memory_pct: 79.0, disk_pct: 47.5, service_up: true },
        }),
      ])
      await delay(CASCADE_STEP_MS)
      await postAll(proxy, [
        serverEvent(server, {
          metrics: { cpu_pct: 88.5, memory_pct: 83.2, disk_pct: 47.5, service_up: true },
        }),
      ])
      return `cascade fired: router + 2 downstream posts 1.5s apart on ${host}`
    }

    case 'duplicate_payload': {
      const forced = `forced-dup-${Date.now()}`
      const dup = serverEvent(server, {
        forced_payload_id: forced,
        metrics: { cpu_pct: 41.0, memory_pct: 63.0, disk_pct: 47.5, service_up: true },
      })
      await postAll(proxy, [dup, { ...dup }])
      return `duplicate payload ${forced} posted twice — Box 2 will block the replay`
    }

    case 'out_of_order': {
      await postAll(proxy, [
        serverEvent(server, {
          event_time_utc: utcIsoNow(OUT_OF_ORDER_OFFSET_MS),
          metrics: { cpu_pct: 38.0, memory_pct: 64.0, disk_pct: 47.5, service_up: true },
        }),
      ])
      return `out-of-order event (T0 = now-90s) accepted on live host ${host}`
    }

    default:
      throw new Error(`unknown scenario ${scenario}`)
  }
}
