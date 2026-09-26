import { AlertCircle, Braces, FileText, Play, RotateCcw, Zap } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import type { Sample } from '../lib/types'
import { Spinner } from './ui'

type Mode = 'sample' | 'raw' | 'json'

export function AlertComposer({
  samples,
  busy,
  onRun,
  onReset,
}: {
  samples: Sample[]
  busy: boolean
  onRun: (alert: Record<string, unknown>) => void
  onReset: () => void
}) {
  const [mode, setMode] = useState<Mode>('sample')
  const [sampleId, setSampleId] = useState(samples[0]?.id ?? '')
  const [raw, setRaw] = useState('')
  const [json, setJson] = useState('')
  const [useLlm, setUseLlm] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const selected = useMemo(
    () => samples.find((s) => s.id === sampleId) ?? samples[0],
    [samples, sampleId],
  )

  const parseError = useMemo(() => {
    if (mode !== 'json') return null
    if (!json.trim()) return 'Paste a JSON object.'
    try {
      const parsed = JSON.parse(json)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return 'Alert must be a JSON object.'
      }
      return null
    } catch (e) {
      return `Invalid JSON — ${(e as Error).message}`
    }
  }, [mode, json])

  const submit = useCallback(() => {
    setError(null)
    if (mode === 'sample') {
      if (!selected) { setError('No samples available.'); return }
      onRun({ ...selected.alert, aegis_use_llm: useLlm })
      return
    }
    if (mode === 'raw') {
      const text = raw.trim()
      if (!text) { setError('Paste a log or alert message first.'); return }
      onRun({ title: 'Manual triage request', description: text.slice(0, 400), raw_log: text, aegis_use_llm: useLlm })
      return
    }
    if (parseError) { setError(parseError); return }
    onRun({ ...JSON.parse(json), aegis_use_llm: useLlm } as Record<string, unknown>)
  }, [mode, selected, raw, json, parseError, useLlm, onRun])

  const MODES: { id: Mode; label: string; icon: typeof Zap }[] = [
    { id: 'sample', label: 'Sample', icon: Zap },
    { id: 'raw', label: 'Raw log', icon: FileText },
    { id: 'json', label: 'Structured JSON', icon: Braces },
  ]

  return (
    <section className="panel">
      <header className="panel-header">
        <h2 className="panel-title">New investigation</h2>
        <div className="ml-auto flex items-center gap-2">
          <label className="flex cursor-pointer select-none items-center gap-1.5 text-2xs text-ink-secondary">
            <input
              type="checkbox"
              checked={useLlm}
              onChange={(e) => setUseLlm(e.target.checked)}
              className="h-3.5 w-3.5 accent-teal-400"
            />
            Tier-2 reasoning
          </label>
          <button type="button" onClick={onReset} className="btn-quiet btn-sm" disabled={busy}>
            <RotateCcw className="h-3.5 w-3.5" />
            Clear
          </button>
        </div>
      </header>

      <div className="p-4">
        {/* Mode switch */}
        <div className="mb-3 flex gap-1 rounded-md border border-line bg-base p-0.5">
          {MODES.map((m) => {
            const Icon = m.icon
            const on = m.id === mode
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => setMode(m.id)}
                aria-pressed={on}
                className={`flex flex-1 items-center justify-center gap-1.5 rounded px-2 py-1.5 text-xs font-medium transition-colors ${
                  on ? 'bg-elevated text-ink shadow-panel' : 'text-ink-muted hover:text-ink-secondary'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {m.label}
              </button>
            )
          })}
        </div>

        {mode === 'sample' && (
          <div className="space-y-2">
            <label className="label" htmlFor="sample">Detection scenario</label>
            <select
              id="sample"
              className="field"
              value={sampleId}
              onChange={(e) => setSampleId(e.target.value)}
            >
              {samples.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.severity} · {s.name}
                </option>
              ))}
            </select>
            {selected && (
              <div className="code mt-1 whitespace-pre-wrap break-all bg-base/50 leading-relaxed">
                {JSON.stringify(selected.alert, null, 1).slice(0, 620)}
                {JSON.stringify(selected.alert).length > 620 ? '\n…' : ''}
              </div>
            )}
          </div>
        )}

        {mode === 'raw' && (
          <div className="space-y-2">
            <label className="label" htmlFor="raw">Raw SIEM log, syslog line or alert text</label>
            <textarea
              id="raw"
              className="field h-40 resize-y font-mono text-xs leading-relaxed"
              placeholder={'2026-09-25 03:14:22 WINDEF: Encoded PowerShell detected\n  Host: FIN-WS-042  User: j.raman  SrcIP: 45.155.205.233\n  Cmd: powershell.exe -w hidden -enc SQBFAFgA…'}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
            />
            <p className="text-2xs text-ink-muted">
              Indicators are extracted from the text, then enriched and mapped automatically.
            </p>
          </div>
        )}

        {mode === 'json' && (
          <div className="space-y-2">
            <label className="label" htmlFor="json">SIEM alert payload (JSON)</label>
            <textarea
              id="json"
              className={`field h-40 resize-y font-mono text-xs leading-relaxed ${parseError ? 'border-critical/60' : ''}`}
              placeholder={'{\n  "title": "Suspicious PowerShell",\n  "severity": "High",\n  "source_ip": "45.155.205.233",\n  "endpoint_hostname": "FIN-WS-042"\n}'}
              value={json}
              onChange={(e) => setJson(e.target.value)}
            />
            {parseError && json.trim() && (
              <p className="flex items-center gap-1.5 text-2xs text-critical">
                <AlertCircle className="h-3.5 w-3.5" /> {parseError}
              </p>
            )}
          </div>
        )}

        {error && (
          <p className="mt-2 flex items-center gap-1.5 text-xs text-critical">
            <AlertCircle className="h-3.5 w-3.5" /> {error}
          </p>
        )}

        <button type="button" onClick={submit} disabled={busy} className="btn-primary btn-md mt-3 w-full">
          {busy ? <Spinner /> : <Play className="h-4 w-4" />}
          {busy ? 'Analysing…' : 'Run investigation'}
        </button>
      </div>
    </section>
  )
}
