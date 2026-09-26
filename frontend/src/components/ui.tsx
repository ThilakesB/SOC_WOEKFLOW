import { Check, Copy, Info } from 'lucide-react'
import { memo, useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

// ── Badge ───────────────────────────────────────────────────────

export function Badge({
  tone = 'text-ink-muted border-line bg-elevated/60',
  children,
  title,
  className = '',
}: {
  tone?: string
  children: ReactNode
  title?: string
  className?: string
}) {
  return (
    <span className={`badge ${tone} ${className}`} title={title}>
      {children}
    </span>
  )
}

// ── Panel ───────────────────────────────────────────────────────

export function Panel({
  title,
  icon,
  action,
  children,
  bodyClass = 'p-4',
  className = '',
}: {
  title?: string
  icon?: ReactNode
  action?: ReactNode
  children: ReactNode
  bodyClass?: string
  className?: string
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <header className="panel-header">
          {icon && <span className="text-ink-muted">{icon}</span>}
          <h2 className="panel-title">{title}</h2>
          <div className="ml-auto flex items-center gap-1.5">{action}</div>
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

// ── Empty state ─────────────────────────────────────────────────

export function Empty({
  icon,
  title,
  hint,
  action,
}: {
  icon: ReactNode
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-elevated text-ink-muted">
        {icon}
      </div>
      <p className="text-sm font-medium text-ink-secondary">{title}</p>
      {hint && <p className="max-w-sm text-xs text-ink-muted">{hint}</p>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

// ── Spinner ─────────────────────────────────────────────────────

export function Spinner({ className = 'h-4 w-4' }: { className?: string }) {
  return (
    <svg className={`animate-spin ${className}`} viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" className="opacity-20" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  )
}

// ── Copy button ─────────────────────────────────────────────────

export const CopyButton = memo(function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false)
  const timer = useRef<number | undefined>(undefined)

  useEffect(() => () => window.clearTimeout(timer.current), [])

  const copy = useCallback(() => {
    navigator.clipboard?.writeText(value).then(() => {
      setDone(true)
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setDone(false), 1400)
    })
  }, [value])

  return (
    <button type="button" onClick={copy} className="btn-quiet btn-sm" aria-label={label}>
      {done ? <Check className="h-3.5 w-3.5 text-benign" /> : <Copy className="h-3.5 w-3.5" />}
      {done ? 'Copied' : label}
    </button>
  )
})

// ── Risk meter ──────────────────────────────────────────────────

export function RiskMeter({ score, label }: { score: number; label?: string }) {
  const clamped = Math.max(0, Math.min(100, score))
  const tone =
    clamped >= 80 ? 'bg-critical' : clamped >= 60 ? 'bg-high' : clamped >= 35 ? 'bg-medium' : clamped >= 15 ? 'bg-low' : 'bg-info'
  const textTone =
    clamped >= 80 ? 'text-critical' : clamped >= 60 ? 'text-high' : clamped >= 35 ? 'text-medium' : clamped >= 15 ? 'text-low' : 'text-info'

  return (
    <div className="flex items-center gap-3">
      <div
        className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-elevated"
        role="meter"
        aria-valuenow={clamped}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Composite risk score"
      >
        <div
          className={`h-full rounded-full transition-[width] duration-500 ease-out ${tone}`}
          style={{ width: `${clamped}%` }}
        />
      </div>
      <span className={`tabular w-11 text-right text-xl font-semibold ${textTone}`}>{clamped}</span>
      {label && <span className="text-2xs text-ink-muted">{label}</span>}
    </div>
  )
}

// ── Confidence bar (inline) ─────────────────────────────────────

export function Confidence({ value }: { value: number }) {
  const tone = value >= 80 ? 'text-benign' : value >= 55 ? 'text-medium' : 'text-ink-muted'
  return (
    <span className={`tabular text-2xs font-semibold ${tone}`} title="Analyst confidence">
      {value}%
    </span>
  )
}

// ── Key/value list ──────────────────────────────────────────────

export function KV({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="kv">
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt>{k}</dt>
          <dd className="font-sans text-xs text-ink-secondary">{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

// ── Tooltip-ish hint ────────────────────────────────────────────

export function Hint({ text }: { text: string }) {
  return (
    <span className="group relative inline-flex">
      <Info className="h-3.5 w-3.5 text-ink-muted" aria-hidden="true" />
      <span
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-20 mb-1.5 w-56 -translate-x-1/2 rounded border border-line bg-overlay px-2.5 py-1.5 text-2xs text-ink-secondary opacity-0 shadow-pop transition-opacity group-hover:opacity-100"
      >
        {text}
      </span>
    </span>
  )
}

// ── Tabs ────────────────────────────────────────────────────────

export function Tabs<T extends string>({
  tabs,
  active,
  onChange,
}: {
  tabs: { id: T; label: string; count?: number }[]
  active: T
  onChange: (id: T) => void
}) {
  return (
    <div role="tablist" className="flex gap-0.5 overflow-x-auto border-b border-line-subtle no-scrollbar">
      {tabs.map((t) => {
        const on = t.id === active
        return (
          <button
            key={t.id}
            role="tab"
            type="button"
            aria-selected={on}
            onClick={() => onChange(t.id)}
            className={`relative shrink-0 px-3 py-2 text-sm font-medium transition-colors ${
              on ? 'text-ink' : 'text-ink-muted hover:text-ink-secondary'
            }`}
          >
            {t.label}
            {t.count !== undefined && t.count > 0 && (
              <span className="tabular ml-1.5 rounded-full bg-elevated px-1.5 text-2xs text-ink-secondary">
                {t.count}
              </span>
            )}
            {on && <span className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-accent" />}
          </button>
        )
      })}
    </div>
  )
}

// ── Stat tile ───────────────────────────────────────────────────

export function Stat({ label, value, tone = 'text-ink' }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="rounded-md border border-line-subtle bg-elevated/40 px-3 py-2.5">
      <p className="text-2xs font-medium uppercase tracking-wider text-ink-muted">{label}</p>
      <p className={`tabular mt-0.5 text-xl font-semibold ${tone}`}>{value}</p>
    </div>
  )
}
