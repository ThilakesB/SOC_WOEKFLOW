import {
  Activity, BookOpen, Crosshair, History, Inbox, Radar, Shield,
  ShieldAlert, Wifi, WifiOff,
} from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { api, investigateStream } from './lib/api'
import type { Health, IncidentRow, Investigation, Sample, Stats, StreamEvent, Technique } from './lib/types'
import { AlertComposer } from './components/AlertComposer'
import { AttackView } from './components/AttackView'
import { IncidentsView } from './components/IncidentsView'
import { KnowledgeView } from './components/KnowledgeView'
import { PipelineStream } from './components/PipelineStream'
import { ReportView } from './components/ReportView'
import { Empty, Spinner } from './components/ui'

type Tab = 'triage' | 'incidents' | 'attack' | 'knowledge'

const NAV: { id: Tab; label: string; icon: typeof Radar }[] = [
  { id: 'triage', label: 'Triage', icon: Radar },
  { id: 'incidents', label: 'Incidents', icon: History },
  { id: 'attack', label: 'ATT&CK', icon: Crosshair },
  { id: 'knowledge', label: 'Knowledge', icon: BookOpen },
]

export default function App() {
  const [tab, setTab] = useState<Tab>('triage')
  const [health, setHealth] = useState<Health | null>(null)
  const [samples, setSamples] = useState<Sample[]>([])
  const [techniques, setTechniques] = useState<Technique[]>([])
  const [rows, setRows] = useState<IncidentRow[]>([])
  const [stats, setStats] = useState<Stats | null>(null)
  const [listLoading, setListLoading] = useState(true)

  const [investigation, setInvestigation] = useState<Investigation | null>(null)
  const [events, setEvents] = useState<StreamEvent[]>([])
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const abort = useRef<AbortController | null>(null)
  const reportRef = useRef<HTMLDivElement>(null)

  // ── bootstrap ──────────────────────────────────────────────────
  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth(null))
    api.samples().then(setSamples).catch(() => setSamples([]))
    api.techniques()
      .then((r) => setTechniques(r.techniques))
      .catch(() => setTechniques([]))
    return () => abort.current?.abort()
  }, [])

  const refreshIncidents = useCallback(() => {
    setListLoading(true)
    api
      .incidents()
      .then((r) => {
        setRows(r.incidents)
        setStats(r.stats)
      })
      .catch(() => undefined)
      .finally(() => setListLoading(false))
  }, [])

  useEffect(() => {
    refreshIncidents()
  }, [refreshIncidents])

  // Health poll keeps provider availability honest without a refresh.
  useEffect(() => {
    const id = window.setInterval(() => {
      api.health().then(setHealth).catch(() => setHealth(null))
    }, 30_000)
    return () => window.clearInterval(id)
  }, [])

  // ── investigation ──────────────────────────────────────────────
  const run = useCallback(
    (raw: Record<string, unknown>) => {
      const { aegis_use_llm: useLlm, ...alert } = raw as { aegis_use_llm?: boolean } & Record<
        string,
        unknown
      >

      abort.current?.abort()
      const ctrl = new AbortController()
      abort.current = ctrl

      setEvents([])
      setInvestigation(null)
      setError(null)
      setRunning(true)
      setTab('triage')

      const onEvent = (e: StreamEvent) => {
        setEvents((prev) => [...prev, e])
        if (e.type === 'result') {
          setInvestigation(e.investigation)
          refreshIncidents()
          window.setTimeout(
            () => reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
            60,
          )
        }
        if (e.type === 'error') setError(e.error)
      }

      investigateStream(alert, useLlm !== false, onEvent, ctrl.signal)
        .catch((err: Error) => {
          if (err.name !== 'AbortError') setError(err.message)
        })
        .finally(() => {
          if (abort.current === ctrl) setRunning(false)
        })
    },
    [refreshIncidents],
  )

  const open = useCallback(async (id: string) => {
    setError(null)
    try {
      setInvestigation(await api.incident(id))
      setEvents([])
      setTab('triage')
      window.setTimeout(
        () => reportRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
        60,
      )
    } catch (e) {
      setError((e as Error).message)
    }
  }, [])

  const reset = useCallback(() => {
    abort.current?.abort()
    setEvents([])
    setInvestigation(null)
    setError(null)
    setRunning(false)
  }, [])

  return (
    <div className="min-h-screen">
      <TopBar health={health} stats={stats} tab={tab} onTab={setTab} />

      <main className="mx-auto max-w-7xl px-4 py-5 sm:px-6">
        {tab === 'triage' && (
          <div className="space-y-4">
            <div className="grid gap-4 lg:grid-cols-[22rem_minmax(0,1fr)]">
              <AlertComposer
                samples={samples}
                busy={running}
                onRun={run}
                onReset={reset}
              />
              <div className="space-y-4">
                <PipelineStream events={events} active={running} error={error} />
                {!investigation && !running && !error && <WelcomePanel samples={samples} onRun={run} />}
                {!investigation && running && <PlaceholderSkeleton />}
              </div>
            </div>

            <div ref={reportRef}>
              {investigation && <ReportView inv={investigation} />}
            </div>
          </div>
        )}

        {tab === 'incidents' && (
          <IncidentsView
            rows={rows}
            stats={stats}
            loading={listLoading}
            onOpen={open}
            onRefresh={refreshIncidents}
          />
        )}

        {tab === 'attack' && <AttackView techniques={techniques} />}

        {tab === 'knowledge' && <KnowledgeView health={health} />}
      </main>

      <Footer />
    </div>
  )
}

// ── chrome ──────────────────────────────────────────────────────

function TopBar({
  health, stats, tab, onTab,
}: {
  health: Health | null
  stats: Stats | null
  tab: Tab
  onTab: (t: Tab) => void
}) {
  const online = health !== null
  const llmReady = health?.llm.some((p) => p.configured && p.reachable) ?? false
  const intelOn = Object.values(health?.intel ?? {}).filter(Boolean).length

  return (
    <header className="sticky top-0 z-30 border-b border-line-subtle bg-base/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5 sm:px-6">
        <div className="flex items-center gap-2">
          <div className="flex h-7 w-7 items-center justify-center rounded-md bg-accent/12 text-accent">
            <Shield className="h-4 w-4" />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold tracking-tight text-ink">AEGIS</p>
            <p className="hidden text-2xs text-ink-muted sm:block">Tier-1 autonomous analyst</p>
          </div>
        </div>

        <nav className="order-3 -mx-1 flex w-full gap-0.5 overflow-x-auto no-scrollbar sm:order-none sm:mx-0 sm:w-auto" aria-label="Views">
          {NAV.map((n) => {
            const Icon = n.icon
            const on = n.id === tab
            return (
              <button
                key={n.id}
                type="button"
                onClick={() => onTab(n.id)}
                aria-current={on ? 'page' : undefined}
                className={`flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  on ? 'bg-elevated text-ink' : 'text-ink-muted hover:bg-elevated/50 hover:text-ink-secondary'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {n.label}
                {n.id === 'incidents' && stats && stats.total > 0 && (
                  <span className="tabular rounded-full bg-elevated px-1.5 text-2xs text-ink-secondary">
                    {stats.total}
                  </span>
                )}
              </button>
            )
          })}
        </nav>

        <div className="ml-auto flex items-center gap-2 text-2xs">
          <StatusPill
            ok={online}
            icon={online ? Wifi : WifiOff}
            label={online ? 'API online' : 'API offline'}
            tone={online ? 'text-benign' : 'text-critical'}
          />          <StatusPill
            ok={llmReady}
            icon={Activity}
            label={
              llmReady
                ? health?.llm.find((p) => p.configured && p.reachable)?.provider ?? 'LLM'
                : 'Deterministic only'
            }
            tone={llmReady ? 'text-accent' : 'text-ink-muted'}
            title={
              llmReady
                ? 'A Tier-2 model provider is configured and reachable.'
                : 'No model provider is configured. Investigations still run the full deterministic pipeline.'
            }
          />
          <span className="hidden text-ink-muted sm:inline" title="Enrichment sources with API keys">
            TI {intelOn}/{Object.keys(health?.intel ?? {}).length || 0}
          </span>
        </div>
      </div>
    </header>
  )
}

function StatusPill({
  ok, icon: Icon, label, tone, title,
}: {
  ok: boolean
  icon: typeof Activity
  label: string
  tone: string
  title?: string
}) {
  return (
    <span
      title={title}
      className={`hidden items-center gap-1 rounded-full border border-line bg-elevated/50 px-2 py-1 font-medium sm:inline-flex ${tone}`}
    >
      <Icon className="h-3 w-3" />
      {label}
      {!ok && <span className="sr-only">unavailable</span>}
    </span>
  )
}

function Footer() {
  return (
    <footer className="border-t border-line-subtle py-4">
      <p className="mx-auto max-w-7xl px-4 text-2xs text-ink-muted sm:px-6">
        AEGIS runs entirely on your infrastructure. Enrichment and model calls are only made to
        providers you configure — everything else is local, and the deterministic pipeline never
        depends on a model being available.
      </p>
    </footer>
  )
}

// ── states ──────────────────────────────────────────────────────

function WelcomePanel({ samples, onRun }: { samples: Sample[]; onRun: (a: Record<string, unknown>) => void }) {
  return (
    <section className="panel">
      <div className="p-5">
        <h2 className="text-lg font-semibold tracking-tight text-ink">Autonomous Tier-1 triage</h2>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-ink-secondary">
          Paste a raw SIEM alert, submit a structured payload, or pick a detection scenario. AEGIS
          extracts indicators, retrieves playbooks and policies, enriches against threat
          intelligence, maps MITRE ATT&CK techniques, scores risk, and produces a containment
          plan — in seconds, without a human in the loop for the analysis itself.
        </p>

        {samples.length > 0 && (
          <>
            <p className="mb-2 mt-4 text-2xs font-semibold uppercase tracking-wider text-ink-muted">
              Detection scenarios
            </p>
            <div className="grid gap-2 sm:grid-cols-2">
              {samples.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => onRun({ ...s.alert, aegis_use_llm: true })}
                  className="group flex items-center gap-2.5 rounded-md border border-line-subtle bg-elevated/30 px-3 py-2 text-left transition-colors hover:border-line hover:bg-elevated/60"
                >
                  <ShieldAlert className="h-4 w-4 shrink-0 text-ink-muted group-hover:text-accent" />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium text-ink-secondary group-hover:text-ink">
                      {s.name}
                    </span>
                    <span className="block truncate text-2xs text-ink-muted">
                      {s.severity} · {s.tactic}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </>
        )}
      </div>
    </section>
  )
}

function PlaceholderSkeleton() {
  return (
    <section className="panel p-4">
      <div className="flex items-center gap-2 text-xs text-ink-muted">
        <Spinner className="h-3.5 w-3.5" /> Building assessment…
      </div>
      <div className="mt-4 space-y-2.5">
        {[100, 92, 60].map((w, i) => (
          <div key={i} className="skeleton h-3" style={{ width: `${w}%` }} />
        ))}
      </div>
    </section>
  )
}

export { Empty, Inbox }
