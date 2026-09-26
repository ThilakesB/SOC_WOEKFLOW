import type { Priority, Severity, Verdict } from './types'

export const SEVERITY_ORDER: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']

export const SEVERITY_TONE: Record<string, string> = {
  Critical: 'text-critical border-critical/35 bg-critical/10',
  High: 'text-high border-high/35 bg-high/10',
  Medium: 'text-medium border-medium/35 bg-medium/10',
  Low: 'text-low border-low/35 bg-low/10',
  Informational: 'text-info border-info/35 bg-info/10',
  Unknown: 'text-info border-info/35 bg-info/10',
}

export const SEVERITY_DOT: Record<string, string> = {
  Critical: 'bg-critical',
  High: 'bg-high',
  Medium: 'bg-medium',
  Low: 'bg-low',
  Informational: 'bg-info',
  Unknown: 'bg-info',
}

export const VERDICT_TONE: Record<Verdict, string> = {
  true_positive: 'text-critical border-critical/35 bg-critical/10',
  suspicious: 'text-suspicious border-suspicious/35 bg-suspicious/10',
  benign: 'text-benign border-benign/35 bg-benign/10',
  unknown: 'text-unknown border-unknown/35 bg-unknown/10',
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: 'True positive',
  suspicious: 'Suspicious',
  benign: 'Benign',
  unknown: 'Unknown',
}

export const PRIORITY_TONE: Record<Priority, string> = {
  P1: 'text-critical border-critical/40 bg-critical/12',
  P2: 'text-high border-high/40 bg-high/12',
  P3: 'text-medium border-medium/40 bg-medium/12',
  P4: 'text-info border-info/40 bg-info/12',
}

export const REPUTATION_TONE: Record<string, string> = {
  malicious: 'text-critical border-critical/35 bg-critical/10',
  vulnerable: 'text-high border-high/35 bg-high/10',
  suspicious: 'text-suspicious border-suspicious/35 bg-suspicious/10',
  low_risk: 'text-low border-low/35 bg-low/10',
  harmless: 'text-benign border-benign/35 bg-benign/10',
  unknown: 'text-ink-muted border-line bg-elevated/60',
}

export const KIND_TONE: Record<string, string> = {
  technique: 'text-accent border-accent/30 bg-accent/10',
  playbook: 'text-low border-low/30 bg-low/10',
  policy: 'text-medium border-medium/30 bg-medium/10',
  query: 'text-info border-info/30 bg-info/10',
}

export const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

/** Map a 0-100 risk score onto a semantic severity. */
export function severityFromScore(score: number): Severity {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 35) return 'Medium'
  if (score >= 15) return 'Low'
  return 'Informational'
}

export function riskTone(score: number): string {
  return SEVERITY_DOT[severityFromScore(score)]
}

export function confidenceTone(conf: number): string {
  if (conf >= 80) return 'text-benign'
  if (conf >= 55) return 'text-medium'
  return 'text-ink-muted'
}

export function formatDuration(ms: number): string {
  if (!ms || ms < 1000) return `${Math.round(ms)}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

export function formatTime(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function relativeTime(iso: string): string {
  const d = new Date(iso).getTime()
  if (Number.isNaN(d)) return ''
  const diff = Date.now() - d
  const mins = Math.round(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.round(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  const days = Math.round(hrs / 24)
  if (days < 30) return `${days}d ago`
  return new Date(iso).toLocaleDateString()
}

export const IOC_TYPE_LABEL: Record<string, string> = {
  ip: 'IPv4', hash: 'File hash', domain: 'Domain', url: 'URL', cve: 'CVE', email: 'Email',
}

/** Shorten long indicators for display without losing recognisability. */
export function truncate(value: string, head = 12, tail = 8): string {
  if (value.length <= head + tail + 1) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/**
 * Minimal, safe markdown renderer for model-authored narrative.
 * Only the subset the analyst prompt can produce is supported: headings,
 * bold, inline code, bullets and blank-line paragraphs. No raw HTML.
 */
export function renderMarkdown(md: string): string {
  const esc = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  const inline = (s: string) =>
    esc(s)
      .replace(/`([^`]+)`/g, '<code class="font-mono text-2xs text-accent bg-base/80 border border-line-subtle rounded px-1 py-0.5">$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong class="text-ink font-semibold">$1</strong>')
      .replace(/(^|[\s(])\*([^*\n]+)\*/g, '$1<em class="text-ink-secondary">$2</em>')

  const out: string[] = []
  let list: string[] = []

  const flush = () => {
    if (list.length) {
      out.push(`<ul class="my-2 space-y-1.5 pl-1">${list.join('')}</ul>`)
      list = []
    }
  }

  for (const raw of md.split('\n')) {
    const line = raw.trimEnd()
    if (!line.trim()) { flush(); continue }
    if (/^#{1,4}\s+/.test(line)) {
      flush()
      const level = (line.match(/^#+/) || ['#'])[0].length
      const text = line.replace(/^#{1,4}\s+/, '')
      const size = level <= 2 ? 'text-sm font-semibold text-ink mt-3 mb-1.5' : 'text-xs font-semibold text-ink-secondary mt-2.5 mb-1'
      out.push(`<p class="${size}">${inline(text)}</p>`)
      continue
    }
    const bullet = line.match(/^\s*[-*•]\s+(.*)$/)
    if (bullet) {
      list.push(
        `<li class="flex gap-2 text-sm text-ink-secondary">
           <span class="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent/70"></span>
           <span class="min-w-0">${inline(bullet[1])}</span>
         </li>`,
      )
      continue
    }
    flush()
    out.push(`<p class="my-1.5 text-sm text-ink-secondary">${inline(line)}</p>`)
  }
  flush()
  return out.join('')
}
