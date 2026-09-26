import {
  AlertTriangle, Ban, Brain, CheckCircle2, ChevronRight, CircleDot,
  Database, Loader2, Radar, Search, Terminal,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { StreamEvent } from '../lib/types'

interface LogLine {
  id: number
  step: string
  message: string
  tool?: string
  ok?: boolean
  summary?: string
  durationMs?: number
  pending?: boolean
}

const STEP_META: Record<string, { label: string; icon: typeof Radar; tone: string }> = {
  extracting: { label: 'Extract indicators', icon: Search, tone: 'text-low' },
  signals: { label: 'Detect behaviour', icon: Radar, tone: 'text-medium' },
  retrieving: { label: 'Retrieve knowledge', icon: Database, tone: 'text-accent' },
  enriching: { label: 'Enrich indicators', icon: Database, tone: 'text-accent' },
  reasoning: { label: 'Tier-2 reasoning', icon: Brain, tone: 'text-accent' },
  tool_call: { label: 'Model invoked tools', icon: Terminal, tone: 'text-high' },
  tool_result: { label: 'Tool result', icon: ChevronRight, tone: 'text-ink-muted' },
  complete: { label: 'Assessment merged', icon: CheckCircle2, tone: 'text-benign' },
  llm_unavailable: { label: 'LLM unavailable — deterministic result retained', icon: AlertTriangle, tone: 'text-medium' },
  llm_error: { label: 'LLM error — deterministic result retained', icon: AlertTriangle, tone: 'text-medium' },
  llm_unparseable: { label: 'Model output not valid JSON', icon: AlertTriangle, tone: 'text-medium' },
}

/** Ordered pipeline phases shown as a progress rail. */
const PHASES = [
  { key: 'extracting', label: 'Extract' },
  { key: 'signals', label: 'Detect' },
  { key: 'retrieving', label: 'Retrieve' },
  { key: 'enriching', label: 'Enrich' },
  { key: 'reasoning', label: 'Reason' },
]

export function PipelineStream({
  events,
  active,
  error,
}: {
  events: StreamEvent[]
  active: boolean
  error: string | null
}) {
  const [lines, setLines] = useState<LogLine[]>([])
  const seq = useRef(0)
  const scrollRef = useRef<HTMLDivElement>(null)

  // Reset when a new run starts.
  useEffect(() => {
    if (active && lines.length === 0) setLines([])
  }, [active]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    for (const e of events) {
      if (e.type !== 'step') continue
      seq.current += 1
      setLines((prev) => [
        ...prev,
        {
          id: seq.current,
          step: e.step,
          message: e.message ?? '',
          tool: e.tool,
          ok: e.ok,
          summary: e.summary,
          durationMs: e.duration_ms,
        },
      ])
    }
  }, [events])

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  if (!active && lines.length === 0 && !error) return null

  const seenPhases = new Set(lines.map((l) => l.step))
  const currentPhase = PHASES.find((p) => !seenPhases.has(p.key))

  return (
    <section className="panel animate-fade-up">
      <header className="panel-header">
        {active ? <Loader2 className="h-4 w-4 animate-spin text-accent" /> : <CheckCircle2 className="h-4 w-4 text-benign" />}
        <h2 className="panel-title">Analysis pipeline</h2>
        {error && (
          <span className="badge ml-auto border-critical/35 bg-critical/10 text-critical">
            <Ban className="h-3 w-3" /> {error.slice(0, 60)}
          </span>
        )}
      </header>

      {/* Phase rail */}
      <div className="flex items-center gap-1 border-b border-line-subtle px-4 py-2.5">
        {PHASES.map((p, i) => {
          const done = seenPhases.has(p.key)
          const isCurrent = currentPhase?.key === p.key && active
          return (
            <div key={p.key} className="flex min-w-0 flex-1 items-center gap-1">
              <div
                className={`flex min-w-0 flex-1 items-center gap-1.5 rounded px-1.5 py-1 text-2xs font-medium transition-colors ${
                  done
                    ? 'bg-benign/10 text-benign'
                    : isCurrent
                      ? 'bg-accent/10 text-accent'
                      : 'text-ink-muted'
                }`}
              >
                {done ? (
                  <CheckCircle2 className="h-3 w-3 shrink-0" />
                ) : isCurrent ? (
                  <Loader2 className="h-3 w-3 shrink-0 animate-spin" />
                ) : (
                  <CircleDot className="h-3 w-3 shrink-0 opacity-50" />
                )}
                <span className="truncate">{p.label}</span>
              </div>
              {i < PHASES.length - 1 && <ChevronRight className="h-3 w-3 shrink-0 text-line-strong" />}
            </div>
          )
        })}
      </div>

      {/* Log */}
      <div ref={scrollRef} className="max-h-64 overflow-y-auto px-4 py-3">
        <ol className="space-y-1.5">
          {lines.map((l) => {
            const meta = STEP_META[l.step] ?? { label: l.step, icon: CircleDot, tone: 'text-ink-muted' }
            const Icon = meta.icon
            return (
              <li key={l.id} className="animate-slide-in flex items-start gap-2 text-xs">
                <Icon className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${meta.tone}`} />
                <div className="min-w-0 flex-1">
                  <span className="font-medium text-ink-secondary">{meta.label}</span>
                  {l.message && <span className="text-ink-muted"> — {l.message}</span>}
                  {l.summary && (
                    <p className="code mt-1 block break-all bg-base/60 leading-relaxed">{l.summary}</p>
                  )}
                </div>
                {l.durationMs !== undefined && (
                  <span className="tabular shrink-0 text-2xs text-ink-muted">{l.durationMs}ms</span>
                )}
                {l.ok === false && <span className="badge shrink-0 border-critical/35 bg-critical/10 text-critical">failed</span>}
              </li>
            )
          })}
          {active && (
            <li className="flex items-center gap-2 pt-1 text-2xs text-ink-muted">
              <Loader2 className="h-3 w-3 animate-spin" /> working…
            </li>
          )}
        </ol>
      </div>
    </section>
  )
}
