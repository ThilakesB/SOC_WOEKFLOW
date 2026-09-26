import { Crosshair, Search, ShieldCheck, Terminal, Wrench, ListOrdered } from 'lucide-react'
import { useMemo, useState } from 'react'
import { TACTIC_ORDER, KIND_TONE } from '../lib/format'
import type { Technique } from '../lib/types'
import { Badge, CopyButton, Empty, Panel } from './ui'

export function AttackView({ techniques }: { techniques: Technique[] }) {
  const [query, setQuery] = useState('')
  const [tactic, setTactic] = useState<string>('All')
  const [selected, setSelected] = useState<Technique | null>(null)

  const tactics = useMemo(
    () => ['All', ...TACTIC_ORDER.filter((t) => techniques.some((x) => x.tactic === t))],
    [techniques],
  )

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    return techniques.filter((t) => {
      if (tactic !== 'All' && t.tactic !== tactic) return false
      if (!q) return true
      return (
        t.id.toLowerCase().includes(q) ||
        t.title.toLowerCase().includes(q) ||
        t.summary.toLowerCase().includes(q) ||
        t.tactic.toLowerCase().includes(q)
      )
    })
  }, [techniques, query, tactic])

  const grouped = useMemo(() => {
    const map = new Map<string, Technique[]>()
    for (const t of filtered) {
      const key = t.tactic || 'Unassigned'
      map.set(key, [...(map.get(key) ?? []), t])
    }
    return TACTIC_ORDER.filter((t) => map.has(t)).map((t) => [t, map.get(t)!] as const)
  }, [filtered])

  if (!techniques.length) {
    return (
      <Panel bodyClass="p-0">
        <Empty icon={<Crosshair className="h-5 w-5" />} title="Knowledge base loading…" />
      </Panel>
    )
  }

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_22rem]">
      <Panel
        title={`ATT&CK techniques (${filtered.length})`}
        icon={<Crosshair className="h-3.5 w-3.5" />}
        bodyClass="p-0"
        action={
          <div className="relative">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              className="field h-7 w-44 pl-7 pr-2 text-xs"
              placeholder="Filter techniques…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Filter techniques"
            />
          </div>
        }
      >
        <div className="flex gap-1 overflow-x-auto border-b border-line-subtle px-3 py-2 no-scrollbar">
          {tactics.map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTactic(t)}
              className={`shrink-0 rounded px-2 py-1 text-2xs font-medium transition-colors ${
                tactic === t ? 'bg-accent/12 text-accent' : 'text-ink-muted hover:text-ink-secondary'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {grouped.length === 0 ? (
          <Empty icon={<Search className="h-5 w-5" />} title="No techniques match" hint="Adjust the filter or search term." />
        ) : (
          <div className="max-h-[36rem] overflow-y-auto">
            {grouped.map(([name, items]) => (
              <div key={name}>
                <h3 className="sticky top-0 z-10 border-y border-line-subtle bg-elevated/95 px-4 py-1.5 text-2xs font-semibold uppercase tracking-wider text-ink-secondary backdrop-blur">
                  {name}
                  <span className="tabular ml-1.5 text-ink-muted">{items.length}</span>
                </h3>
                <ul className="divide-y divide-line-subtle">
                  {items.map((t) => (
                    <li key={t.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(t)}
                        className={`flex w-full items-center gap-3 px-4 py-2 text-left transition-colors hover:bg-elevated/50 ${
                          selected?.id === t.id ? 'bg-accent/8' : ''
                        }`}
                      >
                        <span className="w-20 shrink-0 font-mono text-2xs font-semibold text-accent">{t.id}</span>
                        <span className="min-w-0 flex-1 truncate text-sm text-ink-secondary">{t.title}</span>
                        <span className="tabular hidden shrink-0 text-2xs text-ink-muted sm:block">
                          {t.queries.length}q · {t.remediation.length}r
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <aside className="lg:sticky lg:top-4 lg:self-start">
        {selected ? (
          <TechniqueDetail technique={selected} onClose={() => setSelected(null)} />
        ) : (
          <Panel bodyClass="p-0">
            <Empty
              icon={<Crosshair className="h-5 w-5" />}
              title="Select a technique"
              hint="Each entry carries triage steps, ready-to-adapt detection queries and remediation guidance."
            />
          </Panel>
        )}
      </aside>
    </div>
  )
}

function TechniqueDetail({ technique, onClose }: { technique: Technique; onClose: () => void }) {
  return (
    <Panel
      title={technique.id}
      icon={<Crosshair className="h-3.5 w-3.5" />}
      bodyClass="p-3"
      action={<button onClick={onClose} className="btn-quiet btn-sm">Close</button>}
    >
      <div className="space-y-3">
        <div>
          <h3 className="text-sm font-semibold text-ink">{technique.title}</h3>
          {technique.tactic && (
            <div className="mt-1">
              <Badge tone={KIND_TONE.technique}>{technique.tactic}</Badge>
            </div>
          )}
        </div>

        <p className="text-xs leading-relaxed text-ink-secondary">{technique.summary}</p>

        {technique.triage.length > 0 && (
          <Block title="Triage steps" icon={<ListOrdered className="h-3 w-3" />}>
            <ol className="space-y-1.5">
              {technique.triage.map((s, i) => (
                <li key={i} className="flex gap-2 text-xs text-ink-secondary">
                  <span className="tabular shrink-0 font-semibold text-accent">{i + 1}.</span>
                  {s}
                </li>
              ))}
            </ol>
          </Block>
        )}

        {technique.queries.length > 0 && (
          <Block title="Detection queries" icon={<Terminal className="h-3 w-3" />}>
            <ul className="space-y-1.5">
              {technique.queries.map((q, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <pre className="code min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                    {q}
                  </pre>
                  <CopyButton value={q} label="" />
                </li>
              ))}
            </ul>
          </Block>
        )}

        {technique.remediation.length > 0 && (
          <Block title="Remediation" icon={<Wrench className="h-3 w-3" />}>
            <ul className="space-y-1.5">
              {technique.remediation.map((r, i) => (
                <li key={i} className="flex gap-2 text-xs text-ink-secondary">
                  <ShieldCheck className="mt-0.5 h-3 w-3 shrink-0 text-benign/70" />
                  {r}
                </li>
              ))}
            </ul>
          </Block>
        )}
      </div>
    </Panel>
  )
}

function Block({ title, icon, children }: { title: string; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1.5 flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wider text-ink-muted">
        {icon} {title}
      </p>
      {children}
    </div>
  )
}
