// Thin fetch layer. Every Box 2 call rides the /api proxy (self-signed TLS is
// handled by Vite with secure:false); collector and chaos calls ride /col-a,
// /col-b and /chaos.

async function request(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`
    try {
      const body = await res.json()
      if (body && body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    const err = new Error(detail)
    err.status = res.status
    throw err
  }
  return res.json()
}

export const api = {
  login: (username, password) =>
    request('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  overview: (token) => request('/api/v1/overview', { headers: authHeaders(token) }),

  slaMetrics: (token) => request('/api/v1/sla-metrics', { headers: authHeaders(token) }),

  sourceSeries: (token, sourceId, limit = 120) =>
    request(`/api/v1/sources/${encodeURIComponent(sourceId)}/series?limit=${limit}`, {
      headers: authHeaders(token),
    }),

  thresholds: (token) => request('/api/v1/thresholds', { headers: authHeaders(token) }),

  putThresholds: (token, config) =>
    request('/api/v1/thresholds', {
      method: 'PUT',
      headers: authHeaders(token),
      body: JSON.stringify(config),
    }),

  incidents: (token) => request('/api/v1/incidents', { headers: authHeaders(token) }),

  approveIncident: (token, incidentId) =>
    request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/approve`, {
      method: 'POST',
      headers: authHeaders(token),
    }),

  rollbackIncident: (token, incidentId) =>
    request(`/api/v1/incidents/${encodeURIComponent(incidentId)}/rollback`, {
      method: 'POST',
      headers: authHeaders(token),
    }),

  transitions: (token, limit = 60) =>
    request(`/api/v1/transitions?limit=${limit}`, { headers: authHeaders(token) }),

  collectorStatus: (proxy) => request(`${proxy}/api/status`),

  egressProof: (proxy, limit = 200) => request(`${proxy}/api/egress-proof?limit=${limit}`),

  ingestRaw: (proxy, rawEvent) =>
    request(`${proxy}/api/ingest-raw`, {
      method: 'POST',
      body: JSON.stringify(rawEvent),
    }),

  toggleLink: (proxy) => request(`${proxy}/control/toggle-link`, { method: 'POST' }),

  chaos: (scenario, site) =>
    request(`/chaos/${scenario}?site=${encodeURIComponent(site)}`, { method: 'POST' }),
}

function authHeaders(token) {
  return { Authorization: `Bearer ${token}` }
}

// WebSocket through the /ws proxy -> wss://localhost:8000/ws/{tenant_id}.
export function openTenantSocket(tenantId, jwt, { onFrame, onState }) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const url = `${proto}://${window.location.host}/ws/${encodeURIComponent(tenantId)}?token=${encodeURIComponent(jwt)}`
  let ws
  try {
    ws = new WebSocket(url)
  } catch {
    onState('offline')
    return null
  }
  onState('connecting')
  ws.onopen = () => onState('live')
  ws.onmessage = (evt) => {
    try {
      onFrame(JSON.parse(evt.data))
    } catch {
      /* malformed frame */
    }
  }
  ws.onerror = () => onState('offline')
  ws.onclose = () => onState('offline')
  return ws
}
