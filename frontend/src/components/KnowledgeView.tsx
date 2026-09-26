import { BookOpen, Search, ServerCog, ShieldCheck, Cpu, Database } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { KIND_TONE } from '../lib/format'
import type { Health, RetrievedDoc } from '../lib/types'
import { Badge, Empty, Panel, Spinner } from './ui'

const KINDS = ['all', 'technique', 'playbook', 'policy', 'query'] as const

type Kind = (typeof KINDS)[number]

export function KnowledgeView({ health }: { health: Health | null }) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<Kind>('all')
  const [results, setResults] = useState<RetrievedDoc[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const seq = useRef(0)

  const run = useCallback(
    async (q: string, k: Kind) => {
      if (!q.trim()) { setResults(null); return }
      const id = ++seq.current
      setLoading(true)
      setError(null)
      try {
        const hits = await api.kbSearch(q, 10)
        if (id !== seq.current) return
        setResults(
          (k === 'all' ? hits : hits.filter((h) => h.kind === k)) as unknown as RetrievedDoc[],
        )
      } catch (e) {
        if (id === seq.current) setError((e as Error).message)
      } finally {
        if (id === seq.current) setLoading(false)
      }
    },
    [],
  )

  // Debounced search-as-you-type.
  useEffect(() => {
    const t = window.setTimeout(() => void run(query, kind), 220)
    return () => window.clearTimeout(t)
  }, [query, kind, run])

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <Panel
        title="Knowledge base"
        icon={<BookOpen className="h-3.5 w-3.5" />}
        bodyClass="p-0"
        action={
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              className="field h-7 w-48 pl-7 pr-2 text-xs"
              placeholder="Search playbooks, policy, queries…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search knowledge base"
            />
          </div>
        }
      >
        <div className="flex gap-1 border-b border-line-subtle px-3 py-2">
          {KINDS.map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setKind(k)}
              className={`rounded px-2 py-1 text-2xs font-medium capitalize transition-colors ${
                kind === k ? 'bg-accent/12 text-accent' : 'text-ink-muted hover:text-ink-secondary'
              }`}
            >
              {k}
            </button>
          ))}
        </div>

        {!query.trim() ? (
          <Empty
            icon={<BookOpen className="h-5 w-5" />}
            title="Search the analyst knowledge base"
            hint={
              health
                ? `${health.knowledge_base.documents} documents · ${health.knowledge_base.unique_terms} indexed terms, ranked with BM25. This is the same retrieval layer the agent uses during triage.`
                : undefined
            }
          />
        ) : loading && !results ? (
          <div className="flex justify-center py-12"><Spinner className="h-5 w-5 text-ink-muted" /></div>
        ) : error ? (
          <Empty icon={<Search className="h-5 w-5" />} title="Search failed" hint={error} />
        ) : results && results.length === 0 ? (
          <Empty icon={<Search className="h-5 w-5" />} title="No matches" hint="Try different terms, e.g. 'shadow copy' or 'lateral movement'." />
        ) : (
          <ul className="divide-y divide-line-subtle">
            {results?.map((r) => (
              <li key={r.id} className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-2xs text-accent">{r.id}</span>
                  <Badge tone={KIND_TONE[r.kind] ?? KIND_TONE.query}>{r.kind}</Badge>
                  {r.tactic && <span className="text-2xs text-ink-muted">{r.tactic}</span>}
                  <span className="tabular ml-auto text-2xs text-ink-muted" title="BM25 score">
                    {r.score}
                  </span>
                </div>
                <p className="mt-1 text-sm font-medium text-ink">{r.title}</p>
                <p className="mt-0.5 text-xs leading-relaxed text-ink-muted">{r.excerpt}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <aside className="space-y-3 lg:sticky lg:top-4 lg:self-start">
        <Panel title="System" icon={<ServerCog className="h-3.5 w-3.5" />} bodyClass="p-3">
          {!health ? (
            <div className="flex justify-center py-4"><Spinner className="h-4 w-4 text-ink-muted" /></div>
          ) : (
            <div className="space-y-3">
              <div>
                <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wider text-ink-muted">
                  <Cpu className="mr-1 inline h-3 w-3" /> Model providers
                </p>
                <ul className="space-y-1">
                  {health.llm.map((p) => (
                    <li key={p.provider} className="flex items-center gap-2 text-xs">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          p.reachable ? 'bg-benign' : p.configured ? 'bg-medium' : 'bg-line-strong'
                        }`}
                      />
                      <span className="font-mono text-ink-secondary">{p.provider}</span>
                      <span className="ml-auto text-2xs text-ink-muted">
                        {!p.configured ? 'no key' : p.reachable ? 'ready' : 'unreachable'}
                      </span>
                    </li>
                  ))}
                  {!health.llm.length && (
                    <li className="text-2xs text-ink-muted">No providers configured.</li>
                  )}
                </ul>
              </div>

              <div>
                <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wider text-ink-muted">
                  <Database className="mr-1 inline h-3 w-3" /> Enrichment sources
                </p>
                <ul className="space-y-1">
                  {Object.entries(health.intel).map(([name, on]) => (
                    <li key={name} className="flex items-center gap-2 text-xs">
                      <span className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-benign' : 'bg-line-strong'}`} />
                      <span className="text-ink-secondary">{name}</span>
                      <span className="ml-auto text-2xs text-ink-muted">{on ? 'configured' : 'no key'}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wider text-ink-muted">
                  <ShieldCheck className="mr-1 inline h-3 w-3" /> Knowledge base
                </p>
                <dl className="space-y-0.5 text-xs">
                  {Object.entries(health.knowledge_base.by_kind).map(([k, n]) => (
                    <div key={k} className="flex justify-between">
                      <dt className="capitalize text-ink-secondary">{k}s</dt>
                      <dd className="tabular text-ink-muted">{n}</dd>
                    </div>
                  ))}
                  <div className="flex justify-between border-t border-line-subtle pt-0.5">
                    <dt className="text-ink-secondary">Total</dt>
                    <dd className="tabular font-semibold text-ink">{health.knowledge_base.documents}</dd>
                  </div>
                </dl>
              </div>

              <p className="border-t border-line-subtle pt-2 text-2xs text-ink-muted">
                AEGIS v{health.version}
              </p>
            </div>
          )}
        </Panel>
      </aside>
    </div>
  )
}
