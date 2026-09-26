import { Trash2, History, AlertTriangle, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import { api } from '../lib/api'
import {
  SEVERITY_DOT, SEVERITY_TONE, VERDICT_LABEL, VERDICT_TONE, formatDuration, relativeTime, riskTone,
} from '../lib/format'
import type { IncidentRow, Stats } from '../lib/types'
import { Badge, Empty, Panel, Spinner, Stat } from './ui'

export function IncidentsView({
  rows, stats, loading, onOpen, onRefresh,
}: {
  rows: IncidentRow[]
  stats: Stats | null
  loading: boolean
  onOpen: (id: string) => void
  onRefresh: () => void
}) {
  const [confirmClear, setConfirmClear] = useState(false)
  const [busy, setBusy] = useState(false)

  const clear = async () => {
    setBusy(true)
    try {
      await api.clearIncidents()
      setConfirmClear(false)
      onRefresh()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      {stats && stats.total > 0 && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <Stat label="Investigations" value={stats.total} />
          <Stat
            label="Escalations"
            value={stats.escalations}
            tone={stats.escalations ? 'text-critical' : 'text-ink'}
          />
          <Stat label="Avg risk" value={stats.avg_risk} tone={riskTone(stats.avg_risk)} />
          <Stat label="True positive" value={stats.by_verdict.true_positive ?? 0} tone="text-critical" />
          <Stat label="Avg duration" value={formatDuration(stats.avg_duration_ms)} />
        </div>
      )}

      <Panel
        title="Investigation history"
        icon={<History className="h-3.5 w-3.5" />}
        bodyClass="p-0"
        action={
          rows.length > 0 ? (
            confirmClear ? (
              <span className="flex items-center gap-1.5">
                <span className="text-2xs text-critical">Delete all?</span>
                <button onClick={clear} disabled={busy} className="btn-danger btn-sm">
                  {busy ? <Spinner className="h-3 w-3" /> : <Trash2 className="h-3 w-3" />} Confirm
                </button>
                <button onClick={() => setConfirmClear(false)} className="btn-quiet btn-sm">
                  Cancel
                </button>
              </span>
            ) : (
              <button onClick={() => setConfirmClear(true)} className="btn-quiet btn-sm">
                <Trash2 className="h-3.5 w-3.5" /> Clear
              </button>
            )
          ) : null
        }
      >
        {loading ? (
          <div className="flex justify-center py-12">
            <Spinner className="h-5 w-5 text-ink-muted" />
          </div>
        ) : rows.length === 0 ? (
          <Empty
            icon={<History className="h-5 w-5" />}
            title="No investigations yet"
            hint="Run an investigation from the Triage tab and it will be recorded here automatically."
          />
        ) : (
          <ul className="divide-y divide-line-subtle">
            {rows.map((r) => (
              <li key={r.id}>
                <button
                  type="button"
                  onClick={() => onOpen(r.id)}
                  className="group flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-elevated/50"
                >
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${SEVERITY_DOT[r.severity] ?? 'bg-info'}`} />

                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-ink group-hover:text-ink">{r.title || 'Untitled alert'}</p>
                    <p className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-2xs text-ink-muted">
                      <span className="font-mono">{r.id}</span>
                      <span>{relativeTime(r.created_at)}</span>
                      {r.host && <span className="font-mono">{r.host}</span>}
                      {r.source_ip && <span className="font-mono">{r.source_ip}</span>}
                      <span>{formatDuration(r.duration_ms)}</span>
                      {r.llm_used ? <span className="text-accent">model</span> : null}
                    </p>
                  </div>

                  <div className="hidden shrink-0 items-center gap-2 sm:flex">
                    <Badge tone={VERDICT_TONE[r.verdict] ?? VERDICT_TONE.unknown}>
                      {VERDICT_LABEL[r.verdict] ?? r.verdict}
                    </Badge>
                    <Badge tone={SEVERITY_TONE[r.severity] ?? SEVERITY_TONE.Unknown}>{r.severity}</Badge>
                    <span className={`tabular w-8 text-right text-sm font-semibold ${riskTone(r.risk_score)}`}>
                      {r.risk_score}
                    </span>
                    {r.escalate ? (
                      <AlertTriangle className="h-3.5 w-3.5 text-critical" aria-label="Escalated" />
                    ) : null}
                  </div>

                  <ChevronRight className="h-4 w-4 shrink-0 text-ink-muted transition-transform group-hover:translate-x-0.5" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  )
}
