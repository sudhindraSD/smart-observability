import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { api, openTenantSocket } from './api.js'
import { TENANTS, TENANT_ORDER } from './constants.js'
import { pct95 } from './timefmt.js'
import { fireChaos } from './chaos.js'
import TopBar from './components/TopBar.jsx'
import SlaStrip from './components/SlaStrip.jsx'
import ChaosDrawer from './components/ChaosDrawer.jsx'
import CollectorFleet from './components/CollectorFleet.jsx'
import SourcesPanel from './components/SourcesPanel.jsx'
import IncidentsPanel from './components/IncidentsPanel.jsx'
import TransitionsTable from './components/TransitionsTable.jsx'
import ThresholdsModal from './components/ThresholdsModal.jsx'

const POLL_MS = 5000
const SERIES_POLL_MS = 3000
const LATENCY_WINDOW = 100

const transitionKey = (t) => `${t.entity_id}|${t.new_state}|${t.transition_time_utc}`

function sortDescBy(list, key) {
  return [...list].sort((a, b) => String(b[key] || '').localeCompare(String(a[key] || '')))
}

export default function App() {
  const [tenantId, setTenantId] = useState('bank-a')
  const [jwt, setJwt] = useState('')
  const [wsState, setWsState] = useState('connecting')
  const [tzMode, setTzMode] = useState('UTC')
  const [overview, setOverview] = useState(null)
  const [sla, setSla] = useState(null)
  const [incidents, setIncidents] = useState([])
  const [transitions, setTransitions] = useState([])
  const [latencies, setLatencies] = useState([])
  const [seriesMap, setSeriesMap] = useState({})
  const [selectedSource, setSelectedSource] = useState(null)
  const [thresholdsOpen, setThresholdsOpen] = useState(false)
  const [chaosOpen, setChaosOpen] = useState(false)
  const [linkStatus, setLinkStatus] = useState({})
  const [drillLog, setDrillLog] = useState([])
  const [toast, setToast] = useState(null)
  const [booting, setBooting] = useState(true)
  const [bootError, setBootError] = useState(null)
  const [now, setNow] = useState(() => Date.now())

  const jwtRef = useRef('')
  const tenantRef = useRef('bank-a')
  const wsRef = useRef(null)
  const selectedRef = useRef(null)
  const switchingRef = useRef(false)
  const seriesLoaderRef = useRef(null)
  const seriesDebounceRef = useRef(null)
  const toastTimerRef = useRef(null)

  const showToast = useCallback((kind, text) => {
    setToast({ kind, text })
    clearTimeout(toastTimerRef.current)
    toastTimerRef.current = setTimeout(() => setToast(null), 3800)
  }, [])

  const pushDrill = useCallback((line) => {
    setDrillLog((prev) => [`${new Date().toISOString().slice(11, 19)} ${line}`, ...prev].slice(0, 24))
  }, [])

  const scheduleSeriesRefresh = useCallback(() => {
    clearTimeout(seriesDebounceRef.current)
    seriesDebounceRef.current = setTimeout(() => seriesLoaderRef.current?.(), 700)
  }, [])

  // -- typed WS frame reducer ------------------------------------------------
  const handleFrame = useCallback(
    (frame) => {
      const { type, data } = frame || {}
      if (!data) return
      if (type === 'telemetry') {
        // Browser-side T5 stamp: the exact millisecond the live frame renders.
        const t5 = Date.now()
        const t0 = Date.parse(data.event_time_utc)
        if (!data.is_backlog_replay && !Number.isNaN(t0)) {
          const sample = Math.max(0, (t5 - t0) / 1000) // clamp >= 0 for clock skew
          setLatencies((prev) => [...prev, sample].slice(-LATENCY_WINDOW))
        }
        if (data.source_id) {
          setOverview((ov) => {
            if (!ov) return ov
            return {
              ...ov,
              sources: ov.sources.map((s) =>
                s.source_id === data.source_id
                  ? { ...s, health_state: data.health_state ?? s.health_state, latest_event_time_utc: data.event_time_utc }
                  : s,
              ),
            }
          })
          if (data.source_id === selectedRef.current) scheduleSeriesRefresh()
        }
      } else if (type === 'transition') {
        setTransitions((prev) => {
          if (prev.some((t) => transitionKey(t) === transitionKey(data))) return prev
          return sortDescBy([{ ...data }, ...prev], 'transition_time_utc').slice(0, 80)
        })
      } else if (type === 'incident') {
        setIncidents((prev) =>
          sortDescBy(
            [data, ...prev.filter((i) => i.incident_id !== data.incident_id)],
            'alert_created_utc',
          ),
        )
      } else if (type === 'collector') {
        setOverview((ov) => {
          if (!ov) return ov
          return {
            ...ov,
            collectors: ov.collectors.map((c) =>
              c.collector_id === data.collector_id ? { ...c, ...data } : c,
            ),
          }
        })
      }
    },
    [scheduleSeriesRefresh],
  )

  // -- tenant session bootstrap (auto-login + hard state reset) ---------------
  const switchTenant = useCallback(
    async (nextId) => {
      if (switchingRef.current) return
      switchingRef.current = true
      setBooting(true)
      try {
        if (wsRef.current) {
          wsRef.current.onclose = null
          wsRef.current.close()
          wsRef.current = null
        }
        setWsState('connecting')
        const login = await api.login(TENANTS[nextId].username, TENANTS[nextId].password)
        // Complete reset of previous-tenant state: strict multi-tenant isolation.
        tenantRef.current = nextId
        jwtRef.current = login.access_token
        setTenantId(nextId)
        setJwt(login.access_token)
        setOverview(null)
        setSla(null)
        setIncidents([])
        setTransitions([])
        setLatencies([])
        setSeriesMap({})
        setSelectedSource(null)
        selectedRef.current = null
        setDrillLog([])
        const [ov, sl] = await Promise.all([
          api.overview(login.access_token),
          api.slaMetrics(login.access_token),
        ])
        setOverview(ov)
        setSla(sl)
        setIncidents(sortDescBy(ov.incidents || [], 'alert_created_utc'))
        setTransitions(sortDescBy(ov.recent_transitions || ov.transitions || [], 'transition_time_utc'))
        wsRef.current = openTenantSocket(nextId, login.access_token, {
          onFrame: handleFrame,
          onState: setWsState,
        })
        setBootError(null)
      } catch (err) {
        setBootError(err.message)
      } finally {
        setBooting(false)
        switchingRef.current = false
      }
    },
    [handleFrame],
  )

  useEffect(() => {
    switchTenant('bank-a') // auto-login so the console is alive on first paint
    return () => {
      if (wsRef.current) wsRef.current.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // -- 5s control-plane refresh ----------------------------------------------
  useEffect(() => {
    if (!jwt) return undefined
    const id = setInterval(async () => {
      try {
        const [ov, sl] = await Promise.all([api.overview(jwt), api.slaMetrics(jwt)])
        setOverview(ov)
        setSla(sl)
        setIncidents(sortDescBy(ov.incidents || [], 'alert_created_utc'))
        setTransitions((prev) => {
          const db = (ov.recent_transitions || ov.transitions || []).map(transitionKey)
          const merged = [...(ov.recent_transitions || ov.transitions || []), ...prev.filter((t) => !db.includes(transitionKey(t)))]
          return sortDescBy(merged, 'transition_time_utc').slice(0, 80)
        })
      } catch {
        /* transient poll failure; next tick retries */
      }
    }, POLL_MS)
    return () => clearInterval(id)
  }, [jwt])

  // -- collector link status (both boxes, for the drill drawer) ---------------
  useEffect(() => {
    let alive = true
    const load = async () => {
      const results = {}
      await Promise.all(
        ['/col-a', '/col-b'].map(async (proxy) => {
          try {
            results[proxy] = await api.collectorStatus(proxy)
          } catch {
            results[proxy] = null
          }
        }),
      )
      if (alive) setLinkStatus(results)
    }
    load()
    const id = setInterval(load, POLL_MS)
    return () => {
      alive = false
      clearInterval(id)
    }
  }, [])

  // -- selected source series (history + live appends, event_time ASC) -------
  useEffect(() => {
    if (!jwt || !selectedSource) return undefined
    let alive = true
    const load = async () => {
      try {
        const res = await api.sourceSeries(jwt, selectedSource, 120)
        if (alive) setSeriesMap((m) => ({ ...m, [selectedSource]: res.events || [] }))
      } catch {
        /* transient */
      }
    }
    seriesLoaderRef.current = load
    load()
    const id = setInterval(load, SERIES_POLL_MS)
    return () => {
      alive = false
      clearInterval(id)
      seriesLoaderRef.current = null
    }
  }, [jwt, selectedSource])

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const selectSource = useCallback((sourceId) => {
    selectedRef.current = sourceId
    setSelectedSource(sourceId)
  }, [])

  const liveP95 = useMemo(() => {
    if (!latencies.length) return null
    return pct95([...latencies].sort((a, b) => a - b))
  }, [latencies])

  const runChaos = useCallback(
    async (scenarioId) => {
      const t = TENANTS[tenantRef.current]
      try {
        const msg = await fireChaos(scenarioId, {
          tenantId: t.tenantId,
          proxy: t.collectorProxy,
          liveMode: tenantRef.current === 'bank-a',
        })
        pushDrill(msg)
      } catch (err) {
        pushDrill(`drill failed (${scenarioId}): ${err.message}`)
      }
    },
    [pushDrill],
  )

  const toggleLink = useCallback(async () => {
    const t = TENANTS[tenantRef.current]
    try {
      const res = await api.toggleLink(t.collectorProxy)
      setLinkStatus((s) => ({
        ...s,
        [t.collectorProxy]: { ...(s[t.collectorProxy] || {}), link_enabled: res.link_enabled },
      }))
      pushDrill(res.link_enabled ? `${t.label} collector link restored` : `${t.label} collector link cut`)
    } catch (err) {
      pushDrill(`toggle-link failed: ${err.message}`)
    }
  }, [pushDrill])

  const handleIncidentUpdated = useCallback((record) => {
    setIncidents((prev) =>
      sortDescBy(
        [record, ...prev.filter((i) => i.incident_id !== record.incident_id)],
        'alert_created_utc',
      ),
    )
  }, [])

  const handleApiError = useCallback((msg) => showToast('error', msg), [showToast])

  const tenant = TENANTS[tenantId]

  return (
    <div className="mx-auto max-w-[1560px] px-4 pb-12 pt-3">
      <TopBar
        tenant={tenant}
        tenantId={tenantId}
        tenants={TENANTS}
        tenantOrder={TENANT_ORDER}
        onSwitch={switchTenant}
        tzMode={tzMode}
        onToggleTz={() => setTzMode((m) => (m === 'UTC' ? 'source' : 'UTC'))}
        onOpenThresholds={() => setThresholdsOpen(true)}
        chaosOpen={chaosOpen}
        onToggleChaos={() => setChaosOpen((o) => !o)}
        wsState={wsState}
        now={now}
      />

      <SlaStrip tenant={tenant} sla={sla} liveP95={liveP95} sampleCount={latencies.length} wsState={wsState} now={now} />

      <ChaosDrawer
        open={chaosOpen}
        tenant={tenant}
        tenantId={tenantId}
        linkStatus={linkStatus}
        drillLog={drillLog}
        onRunChaos={runChaos}
        onToggleLink={toggleLink}
      />

      {!overview && booting && (
        <div className="panel mt-3 p-8 text-center text-sm text-slate-400">
          Signing in as <span className="num text-accent">{tenant.username}</span> and attaching to the{' '}
          {tenant.region} control plane…
        </div>
      )}

      {!overview && bootError && !booting && (
        <div className="panel mt-3 border-red-800/60 p-6 text-center">
          <p className="text-sm font-semibold text-red-300">Control plane unreachable</p>
          <p className="mt-1 text-xs text-slate-400">{bootError}</p>
          <button
            type="button"
            onClick={() => switchTenant(tenantId)}
            className="mt-3 rounded-md bg-accent/20 px-3 py-1.5 text-xs font-semibold text-accent ring-1 ring-accent/40 hover:bg-accent/30"
          >
            Retry
          </button>
        </div>
      )}

      {overview && (
        <>
          <CollectorFleet collectors={overview.collectors || []} now={now} />
          <SourcesPanel
            sources={overview.sources || []}
            seriesMap={seriesMap}
            selectedSource={selectedSource}
            onSelect={selectSource}
            tzMode={tzMode}
          />
          <IncidentsPanel
            incidents={incidents}
            jwt={jwt}
            onUpdated={handleIncidentUpdated}
            onError={handleApiError}
          />
          <TransitionsTable transitions={transitions} tzMode={tzMode} />
        </>
      )}

      {thresholdsOpen && (
        <ThresholdsModal
          jwt={jwt}
          onClose={() => setThresholdsOpen(false)}
          onSaved={(msg) => {
            showToast('ok', msg)
            setThresholdsOpen(false)
          }}
          onError={handleApiError}
        />
      )}

      {toast && (
        <div
          className={`slide-up fixed bottom-5 left-1/2 z-50 -translate-x-1/2 rounded-lg px-4 py-2 text-xs font-semibold shadow-xl ring-1 ${
            toast.kind === 'error'
              ? 'bg-red-950/90 text-red-200 ring-red-700/60'
              : 'bg-emerald-950/90 text-emerald-200 ring-emerald-700/60'
          }`}
        >
          {toast.text}
        </div>
      )}
    </div>
  )
}
