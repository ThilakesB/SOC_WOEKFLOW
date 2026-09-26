"""Pydantic contracts shared by the API and the analyst engine."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]
Verdict = Literal["true_positive", "suspicious", "benign", "unknown"]


class AlertIn(BaseModel):
    """SIEM alert payload. Tolerates arbitrary vendor-specific extra fields."""

    title: str | None = None
    description: str | None = None
    severity: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    endpoint_hostname: str | None = None
    user_account: str | None = None
    process_name: str | None = None
    command_line: str | None = None
    file_hash: str | None = None
    file_path: str | None = None
    domain: str | None = None
    url: str | None = None
    email_sender: str | None = None
    rule_name: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    vendor: str | None = None
    timestamp: str | None = None
    raw_log: str | None = None
    model_config = {"extra": "allow"}


class IocSet(BaseModel):
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: dict[str, list[str]] = Field(default_factory=dict)  # algo -> [hash]
    emails: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)

    def total(self) -> int:
        n = len(self.ips) + len(self.domains) + len(self.urls) + len(self.emails) + len(self.cves)
        return n + sum(len(v) for v in self.hashes.values())

    def flatten(self, limit: int = 40) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for ip in self.ips:
            out.append({"type": "ip", "value": ip})
        for d in self.domains:
            out.append({"type": "domain", "value": d})
        for u in self.urls:
            out.append({"type": "url", "value": u})
        for algo, vals in self.hashes.items():
            for v in vals:
                out.append({"type": f"hash_{algo}", "value": v})
        for e in self.emails:
            out.append({"type": "email", "value": e})
        for c in self.cves:
            out.append({"type": "cve", "value": c})
        return out[:limit]


class IntelVerdict(BaseModel):
    indicator: str
    ioc_type: str
    malicious_votes: int = 0
    total_engines: int = 0
    abuse_confidence: int | None = None
    reputation: str = "unknown"
    pulse_count: int | None = None
    malware_families: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    detail: str = ""
    error: str | None = None


class TechniqueHit(BaseModel):
    id: str
    name: str = ""
    tactic: str = ""
    confidence: int = 0
    rationale: str = ""
    playbook_ref: str | None = None
    detection_queries: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)


class RetrievedDoc(BaseModel):
    id: str
    kind: str
    title: str
    score: float
    excerpt: str


class RiskAssessment(BaseModel):
    score: int = 0
    severity: str = "Unknown"
    verdict: Verdict = "unknown"
    confidence: int = 0
    factors: list[dict[str, Any]] = Field(default_factory=list)
    escalate: bool = False
    escalate_reason: str = ""
    sla: str = "T1 / 4h"


class ActionItem(BaseModel):
    action: str
    owner: str = "Tier-1 Analyst"
    priority: Literal["P1", "P2", "P3", "P4"] = "P3"
    automated: bool = False
    requires_approval: bool = False
    rationale: str = ""
    status: Literal["pending", "executed", "approved", "skipped", "failed"] = "pending"


class ToolTrace(BaseModel):
    round: int
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result_summary: str = ""
    ok: bool = True
    duration_ms: int = 0


class Investigation(BaseModel):
    incident_id: str
    created_at: str
    engine: str
    llm_used: bool = False
    alert: dict[str, Any] = Field(default_factory=dict)
    verdict: Verdict = "unknown"
    severity: str = "Unknown"
    confidence: int = 0
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    summary: str = ""
    narrative: str = ""
    attack_chain: list[dict[str, str]] = Field(default_factory=list)
    techniques: list[TechniqueHit] = Field(default_factory=list)
    iocs: IocSet = Field(default_factory=IocSet)
    intel: list[IntelVerdict] = Field(default_factory=list)
    knowledge: list[RetrievedDoc] = Field(default_factory=list)
    actions: list[ActionItem] = Field(default_factory=list)
    timeline: list[dict[str, str]] = Field(default_factory=list)
    escalation: dict[str, Any] = Field(default_factory=dict)
    tool_trace: list[ToolTrace] = Field(default_factory=list)
    analyst_notes: str = ""
    duration_ms: int = 0


class SearchRequest(BaseModel):
    query: str
    kinds: list[str] | None = None
    limit: int = 6
