import {
  AlertOctagon, ArrowRight, BookOpen, Bot, Cpu, Fingerprint, Gauge, GitBranch,
  ListChecks, Radio, ScrollText, Shield, ShieldAlert, Siren, Terminal, Timer, User,
} from 'lucide-react'
import { useState } from 'react'
import {
  KIND_TONE, PRIORITY_TONE, REPUTATION_TONE, SEVERITY_DOT, SEVERITY_TONE,
  VERDICT_LABEL, VERDICT_TONE, formatDuration, formatTime,
  renderMarkdown, truncate,
} from '../lib/format'
import type { Investigation } from '../lib/types'
import { Badge, Confidence, CopyButton, Empty, KV, Panel, RiskMeter, Stat, Tabs } from './ui'

type ReportTab = 'assessment' | 'techniques' | 'indicators' | 'response' | 'evidence'

export function ReportView({ inv }: { inv: Investigation }) {
  const [tab, setTab] = useState<ReportTab>('assessment')
  const alertTitle = (inv.alert.title as string) ?? (inv.alert.rule_name as string) ?? 'Untitled alert'

  const tabs: { id: ReportTab; label: string; count?: number }[] = [
    { id: 'assessment', label: 'Assessment' },
    { id: 'techniques', label: 'ATT&CK', count: inv.techniques.length },
    { id: 'indicators', label: 'Indicators', count: inv.intel.length },
    { id: 'response', label: 'Response', count: inv.actions.length },
    { id: 'evidence', label: 'Evidence', count: inv.knowledge.length + inv.tool_trace.length },
  ]

  return (
    <div className="space-y-4">
      <VerdictHeader inv={inv} title={alertTitle} />

      <div className="panel">
        <Tabs tabs={tabs} active={tab} onChange={setTab} />
        <div className="p-4">
          {tab === 'assessment' && <Assessment inv={inv} />}
          {tab === 'techniques' && <Techniques inv={inv} />}
          {tab === 'indicators' && <Indicators inv={inv} />}
          {tab === 'response' && <Response inv={inv} />}
          {tab === 'evidence' && <Evidence inv={inv} />}
        </div>
      </div>
    </div>
  )
}

// ── header ──────────────────────────────────────────────────────

function VerdictHeader({ inv, title }: { inv: Investigation; title: string }) {
  return (
    <section className="panel animate-fade-up">
      <div className="p-4">
        <div className="flex flex-wrap items-start gap-x-4 gap-y-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <Badge tone={VERDICT_TONE[inv.verdict]}>{VERDICT_LABEL[inv.verdict]}</Badge>
              <Badge tone={SEVERITY_TONE[inv.severity] ?? SEVERITY_TONE.Unknown}>
                <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_DOT[inv.severity] ?? 'bg-info'}`} />
                {inv.severity}
              </Badge>
              {inv.escalation.required && (
                <Badge tone="border-critical/40 bg-critical/12 text-critical">
                  <Siren className="h-3 w-3" /> Escalate {inv.escalation.sla}
                </Badge>
              )}
              <Badge
                tone={inv.llm_used ? 'border-accent/30 bg-accent/10 text-accent' : 'border-line bg-elevated/60 text-ink-muted'}
                title={inv.llm_used ? 'Tier-2 model assessment merged' : 'Deterministic pipeline only — no model available or not used'}
              >
                <Cpu className="h-3 w-3" /> {inv.llm_used ? inv.engine : 'deterministic'}
              </Badge>
            </div>

            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-ink">{title}</h1>

            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-ink-muted">
              <span className="font-mono">{inv.incident_id}</span>
              <span>{formatTime(inv.created_at)}</span>
              <span className="flex items-center gap-1">
                <Timer className="h-3 w-3" /> {formatDuration(inv.duration_ms)}
              </span>
              {inv.analyst_notes && (
                <span className="flex items-center gap-1 text-ink-muted">
                  <ScrollText className="h-3 w-3" /> analyst notes present
                </span>
              )}
            </div>
          </div>

          <div className="w-full shrink-0 sm:w-56">
            <div className="mb-1.5 flex items-baseline justify-between">
              <span className="text-2xs font-medium uppercase tracking-wider text-ink-muted">Composite risk</span>
              <Confidence value={inv.confidence} />
            </div>
            <RiskMeter score={inv.risk.score} />
            <p className="mt-1 text-2xs text-ink-muted">
              Confidence {inv.confidence}% · source severity {inv.risk.source_severity}
            </p>
          </div>
        </div>

        {inv.escalation.required && (
          <div className="mt-3 flex items-start gap-2.5 rounded-md border border-critical/30 bg-critical/8 p-3">
            <AlertOctagon className="mt-0.5 h-4 w-4 shrink-0 text-critical" />
            <div className="min-w-0">
              <p className="text-xs font-semibold text-critical">
                Escalation required — {inv.escalation.sla}
              </p>
              <p className="mt-0.5 text-xs text-ink-secondary">{inv.escalation.reason}</p>
            </div>
          </div>
        )}
      </div>
    </section>
  )
}

// ── assessment tab ──────────────────────────────────────────────

function Assessment({ inv }: { inv: Investigation }) {
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
      <div className="space-y-4">
        <div>
          <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">Summary</h3>
          <p className="text-sm leading-relaxed text-ink-secondary">{inv.summary}</p>
        </div>

        {inv.narrative ? (
          <div>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <Bot className="h-3.5 w-3.5" /> Analyst write-up
            </h3>
            <div
              className="rounded-md border border-line-subtle bg-base/40 px-3.5 py-2.5"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(inv.narrative) }}
            />
          </div>
        ) : (
          <p className="rounded-md border border-dashed border-line bg-base/30 px-3 py-2.5 text-xs text-ink-muted">
            No model narrative. The deterministic pipeline still produced a complete verdict,
            technique mapping, risk breakdown and containment plan.
          </p>
        )}

        {inv.risk.verdict_rationale && (
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              Why this verdict
            </h3>
            <p className="text-sm leading-relaxed text-ink-secondary">{inv.risk.verdict_rationale}</p>
          </div>
        )}

        {inv.attack_chain.length > 0 && (
          <div>
            <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <GitBranch className="h-3.5 w-3.5" /> Attack chain
            </h3>
            <ol className="space-y-0">
              {inv.attack_chain.map((c, i) => (
                <li key={i} className="relative flex gap-3 pb-3 last:pb-0">
                  {i < inv.attack_chain.length - 1 && (
                    <span className="absolute left-[0.4375rem] top-4 h-full w-px bg-line" aria-hidden="true" />
                  )}
                  <span className="relative z-10 mt-1 h-3.5 w-3.5 shrink-0 rounded-full border-2 border-accent bg-base" />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-ink">{c.phase}</p>
                    <p className="text-xs text-ink-secondary">{c.detail}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}

        {inv.analyst_notes && (
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
              What Tier-2 must check
            </h3>
            <p className="text-sm leading-relaxed text-ink-secondary">{inv.analyst_notes}</p>
          </div>
        )}

        <Timeline inv={inv} />
      </div>

      {/* Risk breakdown */}
      <aside className="space-y-3">
        <Panel title="Risk breakdown" icon={<Gauge className="h-3.5 w-3.5" />} bodyClass="p-3">
          <ul className="space-y-2">
            {inv.risk.factors.map((f, i) => (
              <li key={i}>
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-xs text-ink-secondary">{f.name}</span>
                  <span className="tabular text-2xs text-ink-muted">
                    +{f.points}/{f.max}
                  </span>
                </div>
                <div className="mt-1 h-1 overflow-hidden rounded-full bg-elevated">
                  <div
                    className="h-full rounded-full bg-accent/70"
                    style={{ width: `${Math.min(100, (f.points / f.max) * 100)}%` }}
                  />
                </div>
                {f.detail && <p className="mt-0.5 truncate text-2xs text-ink-muted" title={f.detail}>{f.detail}</p>}
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Alert context" icon={<Fingerprint className="h-3.5 w-3.5" />} bodyClass="p-3">
          <KV
            items={[
              ['Host', inv.alert.endpoint_hostname as string],
              ['User', inv.alert.user_account as string],
              ['Source IP', inv.alert.source_ip as string],
              ['Process', inv.alert.process_name as string],
              ['Vendor', inv.alert.vendor as string],
              ['Technique', inv.alert.mitre_technique as string],
            ]}
          />
          {Boolean(inv.alert.command_line) && (
            <div className="mt-2.5">
              <p className="mb-1 flex items-center gap-1 text-2xs font-medium uppercase tracking-wider text-ink-muted">
                <Terminal className="h-3 w-3" /> Command line
              </p>
              <pre className="code block max-h-32 overflow-auto whitespace-pre-wrap break-all leading-relaxed">
                {inv.alert.command_line as string}
              </pre>
            </div>
          )}
        </Panel>
      </aside>
    </div>
  )
}

function Timeline({ inv }: { inv: Investigation }) {
  return (
    <div>
      <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted">
        <Radio className="h-3.5 w-3.5" /> Timeline
      </h3>
      <ol className="space-y-1.5">
        {inv.timeline.map((t, i) => (
          <li key={i} className="flex gap-3 text-xs">
            <span className="tabular w-32 shrink-0 truncate text-ink-muted" title={t.time}>
              {t.time.length > 20 ? formatTime(t.time) : t.time}
            </span>
            <span className="text-ink-secondary">{t.event}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

// ── techniques tab ──────────────────────────────────────────────

function Techniques({ inv }: { inv: Investigation }) {
  if (!inv.techniques.length) {
    return (
      <Empty
        icon={<Shield className="h-5 w-5" />}
        title="No ATT&CK mapping derived"
        hint="No behavioural signal or vendor technique ID matched the knowledge base. This can be legitimate for benign alerts, or it may mean the alert lacks the context needed to map a technique."
      />
    )
  }
  return (
    <ul className="space-y-2.5">
      {inv.techniques.map((t) => (
        <li key={t.id} className="rounded-md border border-line-subtle bg-base/40">
          <div className="flex flex-wrap items-center gap-2 border-b border-line-subtle px-3 py-2">
            <span className="font-mono text-xs font-semibold text-accent">{t.id}</span>
            <span className="text-sm font-medium text-ink">{t.name}</span>
            {t.tactic && <Badge tone="border-line bg-elevated/60 text-ink-secondary">{t.tactic}</Badge>}
            <span className="ml-auto flex items-center gap-1.5">
              <Confidence value={t.confidence} />
              <div className="h-1 w-16 overflow-hidden rounded-full bg-elevated">
                <div className="h-full rounded-full bg-accent/70" style={{ width: `${t.confidence}%` }} />
              </div>
            </span>
          </div>

          <div className="space-y-2.5 px-3 py-2.5">
            {t.rationale && <p className="text-xs leading-relaxed text-ink-secondary">{t.rationale}</p>}

            {t.detection_queries.length > 0 && (
              <QueryList title="Detection queries" queries={t.detection_queries} />
            )}
            {t.remediation.length > 0 && (
              <div>
                <p className="mb-1 text-2xs font-medium uppercase tracking-wider text-ink-muted">Remediation</p>
                <ul className="space-y-1">
                  {t.remediation.map((r, i) => (
                    <li key={i} className="flex gap-2 text-xs text-ink-secondary">
                      <ShieldAlert className="mt-0.5 h-3 w-3 shrink-0 text-medium/70" />
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </li>
      ))}
    </ul>
  )
}

function QueryList({ title, queries }: { title: string; queries: string[] }) {
  return (
    <div>
      <p className="mb-1 text-2xs font-medium uppercase tracking-wider text-ink-muted">{title}</p>
      <ul className="space-y-1">
        {queries.map((q, i) => (
          <li key={i} className="flex items-start gap-1.5">
            <pre className="code min-w-0 flex-1 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
              {q}
            </pre>
            <CopyButton value={q} label="" />
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── indicators tab ──────────────────────────────────────────────

function Indicators({ inv }: { inv: Investigation }) {
  const buckets: [string, string[]][] = [
    ['IPv4', inv.iocs.ips],
    ['Domains', inv.iocs.domains],
    ['URLs', inv.iocs.urls],
    ['File hashes', Object.values(inv.iocs.hashes).flat()],
    ['Emails', inv.iocs.emails],
    ['CVEs', inv.iocs.cves],
  ]
  const found = buckets.filter(([, v]) => v.length > 0)

  return (
    <div className="space-y-4">
      {found.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-muted">Extracted</h3>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {found.map(([label, values]) => (
              <div key={label} className="rounded-md border border-line-subtle bg-base/40 p-2.5">
                <p className="mb-1.5 flex items-center gap-1.5 text-2xs font-medium uppercase tracking-wider text-ink-muted">
                  <Fingerprint className="h-3 w-3" /> {label}
                  <span className="tabular ml-auto text-ink-muted">{values.length}</span>
                </p>
                <ul className="space-y-1">
                  {values.map((v) => (
                    <li key={v} className="flex items-center gap-1">
                      <code className="min-w-0 flex-1 truncate font-mono text-2xs text-ink-secondary" title={v}>
                        {v}
                      </code>
                      <CopyButton value={v} label="" />
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-muted">
          Threat intelligence
        </h3>
        {inv.intel.length === 0 ? (
          <p className="rounded-md border border-dashed border-line bg-base/30 px-3 py-2.5 text-xs text-ink-muted">
            No indicators were available to enrich.
          </p>
        ) : (
          <div className="space-y-1.5">
            {inv.intel.map((v, i) => {
              const err = (v.detail?.errors as string[] | undefined) ?? (v.error ? [v.error] : [])
              return (
                <div key={i} className="rounded-md border border-line-subtle bg-base/40 px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <code className="font-mono text-xs text-ink" title={v.indicator}>
                      {truncate(v.indicator, 18, 10)}
                    </code>
                    <Badge tone="border-line bg-elevated/60 text-ink-secondary">{v.ioc_type}</Badge>
                    <Badge tone={REPUTATION_TONE[v.reputation] ?? REPUTATION_TONE.unknown}>
                      {v.reputation}
                    </Badge>
                    {v.cached && <span className="text-2xs text-ink-muted">cached</span>}
                    <span className="ml-auto flex items-center gap-2 text-2xs text-ink-muted">
                      {v.total_engines > 0 && (
                        <span className="tabular">
                          <span className={v.malicious_votes > 0 ? 'text-critical' : 'text-benign'}>
                            {v.malicious_votes}
                          </span>
                          /{v.total_engines} engines
                        </span>
                      )}
                      {v.abuse_confidence != null && (
                        <span className="tabular">abuse {v.abuse_confidence}%</span>
                      )}
                      {v.pulse_count != null && <span className="tabular">{v.pulse_count} pulses</span>}
                    </span>
                  </div>

                  {v.malware_families.length > 0 && (
                    <p className="mt-1 text-2xs text-ink-secondary">
                      Families: {v.malware_families.join(', ')}
                    </p>
                  )}
                  {typeof v.detail?.description === 'string' && v.detail.description && (
                    <p className="mt-1 text-2xs leading-relaxed text-ink-muted">{v.detail.description}</p>
                  )}
                  <p className="mt-1 text-2xs text-ink-muted">
                    Sources: {v.sources.length ? v.sources.join(', ') : 'none configured'}
                    {err.length > 0 && <span className="text-medium"> · {err[0]}</span>}
                  </p>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

// ── response tab ────────────────────────────────────────────────

function Response({ inv }: { inv: Investigation }) {
  const automated = inv.actions.filter((a) => a.automated).length
  const approval = inv.actions.filter((a) => a.requires_approval).length
  const priorities = ['P1', 'P2', 'P3', 'P4'] as const

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <Stat label="Planned" value={inv.actions.length} />
        <Stat label="Automated" value={automated} tone="text-accent" />
        <Stat label="Needs approval" value={approval} tone={approval ? 'text-medium' : 'text-ink-muted'} />
      </div>

      <p className="rounded-md border border-line-subtle bg-base/40 px-3 py-2 text-2xs leading-relaxed text-ink-muted">
        This is a proposed containment plan, not an executed one. AEGIS has no EDR or identity
        connector wired up yet, so every action below is{' '}
        <span className="text-medium">pending</span> and must be carried out by an operator.
        Items marked <span className="text-accent">automated</span> fall inside the Tier-1
        containment authority and need no separate approval; anything marked{' '}
        <span className="text-medium">approval required</span> is gated to a named human per
        policy PO-CONTAINMENT.
      </p>

      {priorities.map((p) => {
        const group = inv.actions.filter((a) => a.priority === p)
        if (!group.length) return null
        return (
          <div key={p}>
            <div className="mb-1.5 flex items-center gap-2">
              <Badge tone={PRIORITY_TONE[p]}>{p}</Badge>
              <span className="text-2xs text-ink-muted">{group.length} action{group.length > 1 ? 's' : ''}</span>
            </div>
            <ul className="space-y-1.5">
              {group.map((a, i) => (
                <li key={i} className="rounded-md border border-line-subtle bg-base/40 px-3 py-2">
                  <div className="flex items-start gap-2">
                    <ListChecks
                      className={`mt-0.5 h-3.5 w-3.5 shrink-0 ${a.requires_approval ? 'text-medium' : 'text-accent'}`}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm text-ink">{a.action}</p>
                      {a.rationale && <p className="mt-0.5 text-2xs leading-relaxed text-ink-muted">{a.rationale}</p>}
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        <Badge
                          tone={
                            a.requires_approval
                              ? 'border-medium/35 bg-medium/10 text-medium'
                              : 'border-accent/30 bg-accent/10 text-accent'
                          }
                        >
                          {a.requires_approval ? 'Approval required' : 'Automated'}
                        </Badge>
                        <Badge tone="border-line bg-elevated/60 text-ink-muted">
                          <span className="h-1.5 w-1.5 rounded-full bg-line-strong" />
                          {a.status}
                        </Badge>
                        <span className="text-2xs text-ink-muted">{a.owner}</span>
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )
      })}
    </div>
  )
}

// ── evidence tab ────────────────────────────────────────────────

function Evidence({ inv }: { inv: Investigation }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Retrieved knowledge" icon={<BookOpen className="h-3.5 w-3.5" />} bodyClass="p-3">
        {inv.knowledge.length === 0 ? (
          <p className="text-xs text-ink-muted">No knowledge base documents retrieved.</p>
        ) : (
          <ul className="space-y-2">
            {inv.knowledge.map((k) => (
              <li key={k.id} className="rounded-md border border-line-subtle bg-base/40 p-2.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-2xs text-accent">{k.id}</span>
                  <Badge tone={KIND_TONE[k.kind] ?? KIND_TONE.query}>{k.kind}</Badge>
                  <span className="tabular ml-auto text-2xs text-ink-muted" title="BM25 relevance">
                    {k.score}
                  </span>
                </div>
                <p className="mt-1 text-xs font-medium text-ink-secondary">{k.title}</p>
                <p className="mt-0.5 text-2xs leading-relaxed text-ink-muted">{k.excerpt}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="Model tool calls" icon={<Bot className="h-3.5 w-3.5" />} bodyClass="p-3">
        {inv.tool_trace.length === 0 ? (
          <p className="text-xs text-ink-muted">
            No model tool calls. Either the Tier-2 layer was not used, or it answered without
            needing external lookups.
          </p>
        ) : (
          <ol className="space-y-2">
            {inv.tool_trace.map((t, i) => (
              <li key={i} className="rounded-md border border-line-subtle bg-base/40 p-2.5">
                <div className="flex items-center gap-2">
                  <span className="tabular text-2xs text-ink-muted">r{t.round}</span>
                  <span className="font-mono text-xs text-accent">{t.name}</span>
                  <span className="tabular ml-auto text-2xs text-ink-muted">{t.duration_ms}ms</span>
                </div>
                {Object.keys(t.arguments).length > 0 && (
                  <pre className="code mt-1.5 block overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                    {JSON.stringify(t.arguments)}
                  </pre>
                )}
                {t.result_summary && (
                  <p className="mt-1.5 break-all text-2xs leading-relaxed text-ink-muted">{t.result_summary}</p>
                )}
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  )
}

export { ArrowRight, User }
