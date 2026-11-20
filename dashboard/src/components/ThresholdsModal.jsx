import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import { api } from '../api.js'
import { Spinner } from './ui.jsx'

// Live threshold editor. GET /api/v1/thresholds returns {tenant_id, config,
// updated_utc}; PUT takes the flat ThresholdConfig object itself (confirmed in
// saas/main.py), so inputs are rendered dynamically from the GET response and
// the whole object is PUT back with original numeric types preserved.
export default function ThresholdsModal({ jwt, onClose, onSaved, onError }) {
  const [config, setConfig] = useState(null)
  const [original, setOriginal] = useState(null)
  const [meta, setMeta] = useState({ tenant: '', updated: null })
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    let alive = true
    api
      .thresholds(jwt)
      .then((res) => {
        if (!alive) return
        setConfig({ ...(res.config || {}) })
        setOriginal({ ...(res.config || {}) })
        setMeta({ tenant: res.tenant_id, updated: res.updated_utc })
      })
      .catch((err) => {
        if (alive) onError(err.message)
      })
    return () => {
      alive = false
    }
  }, [jwt, onError])

  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const save = async () => {
    setSaving(true)
    try {
      const payload = {}
      for (const [key, value] of Object.entries(config)) {
        const was = original?.[key]
        if (typeof was === 'number') {
          const n = Number(value)
          payload[key] = Number.isFinite(n) ? (Number.isInteger(was) ? Math.round(n) : n) : was
        } else if (typeof was === 'boolean') {
          payload[key] = Boolean(value)
        } else {
          payload[key] = value
        }
      }
      const res = await api.putThresholds(jwt, payload)
      onSaved(`Thresholds saved for ${res.tenant_id} · ${res.updated_utc}`)
    } catch (err) {
      onError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const inputCls =
    'num mt-0.5 w-full rounded-md bg-panel-2/80 px-2 py-1.5 text-[12px] text-slate-100 ring-1 ring-[var(--color-edge)] outline-none focus:ring-accent/60'

  return (
    <div
      className="fixed inset-0 z-40 grid place-items-center bg-black/70 p-4 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="panel slide-up max-h-[86vh] w-full max-w-xl overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-[var(--color-edge)] px-4 py-3">
          <div>
            <h2 className="text-[12px] font-bold uppercase tracking-[0.14em] text-slate-300">
              Health Thresholds
            </h2>
            <p className="num mt-0.5 text-[10px] text-slate-500">
              tenant {meta.tenant || '…'}
              {meta.updated ? ` · updated ${meta.updated}` : ''}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-slate-400 hover:bg-panel-2 hover:text-slate-100"
          >
            <X size={14} />
          </button>
        </header>

        <div className="p-4">
          {!config ? (
            <Spinner label="Loading thresholds…" />
          ) : (
            <>
              <div className="grid gap-2 sm:grid-cols-2">
                {Object.entries(config).map(([key, value]) => (
                  <label key={key} className="block">
                    <span className="num block text-[10px] font-semibold uppercase tracking-wide text-slate-500">
                      {key}
                    </span>
                    {typeof value === 'boolean' ? (
                      <input
                        type="checkbox"
                        checked={value}
                        onChange={(e) =>
                          setConfig((c) => ({ ...c, [key]: e.target.checked }))
                        }
                        className="mt-1.5 h-4 w-4 accent-[#38e8c8]"
                      />
                    ) : typeof value === 'number' ? (
                      <input
                        type="number"
                        step="any"
                        min="0"
                        value={String(value)}
                        onChange={(e) =>
                          setConfig((c) => ({
                            ...c,
                            [key]: e.target.value === '' ? '' : Number(e.target.value),
                          }))
                        }
                        className={inputCls}
                      />
                    ) : (
                      <input
                        type="text"
                        value={String(value)}
                        onChange={(e) => setConfig((c) => ({ ...c, [key]: e.target.value }))}
                        className={inputCls}
                      />
                    )}
                  </label>
                ))}
              </div>
              <div className="mt-4 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-md bg-panel-2/80 px-3 py-1.5 text-[11px] font-semibold text-slate-300 ring-1 ring-[var(--color-edge)] transition hover:text-slate-100"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={save}
                  disabled={saving}
                  className={`rounded-md px-3 py-1.5 text-[11px] font-semibold ring-1 transition ${
                    saving
                      ? 'cursor-not-allowed bg-slate-800/60 text-slate-500 ring-slate-700/50'
                      : 'bg-accent/20 text-accent ring-accent/50 hover:bg-accent/30'
                  }`}
                >
                  {saving ? 'Saving…' : 'Save Thresholds'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
