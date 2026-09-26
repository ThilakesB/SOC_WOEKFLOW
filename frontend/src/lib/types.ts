export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type Verdict = 'true_positive' | 'suspicious' | 'benign' | 'unknown'
export type Priority = 'P1' | 'P2' | 'P3' | 'P4'

export interface ToolTrace {
  round: number
  name: string
  arguments: Record<string, unknown>
  result_summary: string
  ok: boolean
  duration_ms: number
}

export interface TechniqueHit {
  id: string
  name: string
  tactic: string
  confidence: number
  rationale: string
  playbook_ref: string | null
  detection_queries: string[]
  remediation: string[]
}

export interface IntelVerdict {
  indicator: string
  ioc_type: string
  malicious_votes: number
  total_engines: number
  abuse_confidence: number | null
  pulse_count: number | null
  reputation: string
  malware_families: string[]
  sources: string[]
  detail: Record<string, unknown>
  error?: string | null
  cached?: boolean
}

export interface IocSet {
  ips: string[]
  domains: string[]
  urls: string[]
  hashes: Record<string, string[]>
  emails: string[]
  cves: string[]
}

export interface RiskFactor {
  name: string
  points: number
  max: number
  detail: string
}

export interface RiskAssessment {
  score: number
  severity: string
  source_severity: string
  verdict: Verdict
  confidence: number
  factors: RiskFactor[]
  escalate: boolean
  escalate_reason: string
  sla: string
  verdict_rationale: string
}

export interface ActionItem {
  action: string
  owner: string
  priority: Priority
  automated: boolean
  requires_approval: boolean
  rationale: string
  status: 'pending' | 'executed' | 'approved' | 'skipped' | 'failed'
}

export interface RetrievedDoc {
  id: string
  kind: string
  title: string
  score: number
  tactic?: string
  excerpt: string
}

export interface Investigation {
  incident_id: string
  created_at: string
  engine: string
  llm_used: boolean
  alert: Record<string, unknown>
  verdict: Verdict
  severity: string
  confidence: number
  risk: RiskAssessment
  summary: string
  narrative: string
  attack_chain: { phase: string; detail: string }[]
  techniques: TechniqueHit[]
  iocs: IocSet
  intel: IntelVerdict[]
  knowledge: RetrievedDoc[]
  actions: ActionItem[]
  timeline: { time: string; event: string }[]
  escalation: { required: boolean; reason: string; sla: string }
  tool_trace: ToolTrace[]
  analyst_notes: string
  duration_ms: number
}

export interface IncidentRow {
  id: string
  created_at: string
  engine: string
  llm_used: number
  verdict: Verdict
  severity: string
  confidence: number
  risk_score: number
  title: string | null
  host: string | null
  source_ip: string | null
  escalate: number
  duration_ms: number
}

export interface Stats {
  total: number
  by_severity: Record<string, number>
  by_verdict: Record<string, number>
  avg_risk: number
  avg_duration_ms: number
  escalations: number
}

export interface Technique {
  id: string
  title: string
  tactic: string
  summary: string
  triage: string[]
  queries: string[]
  remediation: string[]
}

export interface Sample {
  id: string
  name: string
  severity: string
  tactic: string
  alert: Record<string, unknown>
}

export interface Health {
  status: string
  version: string
  llm: { provider: string; configured: boolean; reachable: boolean }[]
  llm_chain: string[]
  intel: Record<string, boolean>
  knowledge_base: { documents: number; unique_terms: number; by_kind: Record<string, number> }
}

export type StreamEvent =
  | { type: 'step'; step: string; at: string; message?: string; tool?: string; ok?: boolean; summary?: string; duration_ms?: number; tools?: string[]; raw_excerpt?: string }
  | { type: 'result'; investigation: Investigation }
  | { type: 'error'; error: string }
  | { type: 'done' }
