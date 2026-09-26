"""Tier-1 analyst engine.

Two layers:

  1. Deterministic pass — IOC extraction, enrichment, retrieval, ATT&CK
     mapping, risk scoring, verdict, escalation and action planning.
     Runs with zero LLM calls and always produces a complete report.

  2. Agentic pass — an LLM with tools that interrogates the evidence, calls
     enrichment and retrieval on demand, and writes the analyst narrative.
     It refines the deterministic result; it never invents the verdict alone.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import re
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable

from . import kb_data, rag, tools
from .config import settings
from .llm import LLMError, Router, Tool, decode_payload, parse_json_loose

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High", "Critical"]
SEV_ALIASES = {
    "info": "Informational", "informational": "Informational", "information": "Informational",
    "1": "Informational", "low": "Low", "2": "Low",
    "med": "Medium", "medium": "Medium", "moderate": "Medium", "3": "Medium",
    "high": "High", "severe": "High", "4": "High",
    "critical": "Critical", "crit": "Critical", "emergency": "Critical", "5": "Critical",
    "p1": "Critical", "p2": "High", "p3": "Medium", "p4": "Low",
}

CRITICAL_ASSETS = {
    "dc01", "dc02", "domaincontroller", "vcenter", "esxi", "backup", "sql01", "sql02",
    "exchange", "adfs", "krbtgt", "pam", "vault", "hsm", "scanner", "siem", "splunk",
}
PRIVILEGED_HINTS = ("admin", "root", "svc_", "service", "sa", "administrator", "da_", "ea_")

# Behaviour signals that are independently alarming regardless of intel.
BEHAVIOUR_SIGNALS: list[tuple[str, str, str, int]] = [
    (r"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog", "Shadow copy deletion", "T1486", 30),
    (r"(?i)bcdedit.*recoveryenabled\s+no", "Recovery disabling", "T1486", 28),
    (r"(?i)comsvcs\.dll.*MiniDump|procdump.*lsass", "LSASS memory dump", "T1003", 30),
    (r"(?i)reg\s+save.*\\\\(SAM|SECURITY|SYSTEM)", "Registry hive dump", "T1003", 26),
    (r"(?i)ntdsutil|vssadmin.*create\s+shadow", "NTDS/volume shadow access", "T1003", 26),
    (r"(?i)-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}", "Encoded PowerShell", "T1059.001", 20),
    (r"(?i)DownloadString|FromBase64String|Invoke-Expression|\bIEX\b", "In-memory download cradle", "T1059.001", 22),
    (r"(?i)certutil.*-urlcache|bitsadmin\s+/transfer", "LOLB remote download", "T1218", 20),
    (r"(?i)mshta\s+http|rundll32.*javascript:|regsvr32.*scrobj", "Signed-binary proxy execution", "T1218", 22),
    (r"(?i)wmic.*/node:.*process\s+call\s+create", "Remote WMI execution", "T1021", 18),
    (r"(?i)schtasks\s+/create.*(/ru\s+system|highest)", "Privileged scheduled task", "T1053", 20),
    (r"(?i)rundll32|regsvr32|mshta|bitsadmin", "Signed binary abuse", "T1218", 12),
    (r"(?i)Invoke-Command|Enter-PSSession|New-PSSession", "PowerShell remoting", "T1021", 16),
    (r"(?i)lsass\.exe", "lsass reference", "T1003", 10),
    (r"(?i)cmd\.exe\s*/c\s+.*whoami|/net\s+user|/domain", "Discovery command", "T1087", 12),
    (r"(?i)net\s+user\s+/add|net\s+localgroup\s+.*/add", "Account or group creation", "T1136", 22),
    (r"(?i)reg\s+add.*\\\\Run|CurrentVersion\\\\Run", "Persistence registry key", "T1547", 20),
    (r"(?i)at\s+\\\\|schtasks", "Scheduled task abuse", "T1053", 16),
    (r"(?i)secretsdump|mimikatz|sekurlsa|lsadump|kerberoast", "Credential dumping tooling", "T1003", 28),
    (r"(?i)psexec|paexec|smbexec", "Remote execution tooling", "T1021", 20),
    (r"(?i)keylogger|keylog|capslock.*log|clipboard.*exfil", "Collection tooling", "T1056", 20),
    (r"(?i)4625|failed logon|failed login|authentication fail|invalid credential", "Authentication failure burst", "T1110", 18),
    (r"(?i)\brdp\b|3389|terminal service|mstsc|remote desktop", "RDP activity", "T1021.001", 14),
    (r"(?i)wget|curl\b|Invoke-WebRequest|DownloadFile|Start-BitsTransfer", "Tool transfer", "T1105", 16),
    (r"(?i)cobalt\s*strike|meterpreter|mimikatz.*(ps1|dll)|Invoke-Mimikatz", "Adversary framework tooling", "T1059.001", 26),
    (r"(?i)ransomware|lockbit|conti|ryuk|blackcat|locker|alphabetic|wannacry", "Ransomware family reference", "T1486", 30),
    (r"(?i)\.onion\b|tor\s*proxy|torbrowser", "Tor anonymisation", "T1090", 20),
    (r"(?i)whoami\s*/priv|net\s+user\s+/domain|quser\s|net\s+group", "Account or host discovery", "T1087", 12),
    (r"(?i)wevtutil\s+cl|clear-eventlog|Clear-EventLog", "Log clearing", "T1070", 26),
    (r"(?i)netsh\s+.*firewall.*(add|set)|Set-NetFirewallProfile.*disable", "Firewall tampering", "T1562", 20),
]

ASSESSMENT_PROMPT = """You are a Tier-2 SOC analyst reviewing a Tier-1 automated triage of a
security alert. You have tools to query threat intelligence and the internal knowledge base.
Ground every claim in the evidence provided or returned by a tool. Never invent indicators,
techniques, or facts. If evidence is absent, say so explicitly.

Return ONLY a JSON object with this exact shape:
{
  "verdict": "true_positive|suspicious|benign|unknown",
  "severity": "Critical|High|Medium|Low|Informational",
  "confidence": 0-100,
  "summary": "3-5 sentence factual summary of what happened and why you reached this verdict",
  "narrative": "Markdown analyst write-up: What happened / Evidence / Assessment / Why this verdict. Cite technique IDs and indicator verdicts inline.",
  "attack_chain": [{"phase": "Initial Access", "detail": "..."}],
  "techniques": [{"id": "T1059.001", "confidence": 0-100, "rationale": "why this maps"}],
  "analyst_notes": "What Tier-2 must check next, and what you ruled out",
  "escalation": {"required": true, "reason": "which escalation trigger fired"},
  "actions": [{"action": "...", "priority": "P1|P2|P3|P4", "rationale": "..."}],
  "timeline": [{"time": "...", "event": "..."}]
}"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return "INC-" + uuid.uuid4().hex[:8].upper()


def normalise_severity(value: Any) -> str:
    if not value:
        return "Medium"
    v = str(value).strip().lower()
    return SEV_ALIASES.get(v, v.capitalize() if v.capitalize() in SEVERITY_ORDER else "Medium")


def _is_critical_asset(alert: dict) -> bool:
    blob = " ".join(
        str(alert.get(k, "")) for k in ("endpoint_hostname", "title", "description", "process_name")
    ).lower()
    return any(a in blob for a in CRITICAL_ASSETS)


def _is_privileged(alert: dict) -> bool:
    user = str(alert.get("user_account", "")).lower()
    return any(h in user for h in PRIVILEGED_HINTS)


# ── layer 1: deterministic ───────────────────────────────────────

def detect_signals(alert: dict, raw_text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for pattern, label, tid, weight in BEHAVIOUR_SIGNALS:
        m = re.search(pattern, raw_text)
        if m:
            hits.append({
                "label": label,
                "technique": tid,
                "weight": weight,
                "evidence": (m.group(0) or label)[:160],
            })
    return hits


def map_techniques(alert: dict, raw_text: str, signals: list[dict],
                   docs: list[dict]) -> list[dict[str, Any]]:
    """Build ATT&CK technique hits from explicit ids, signals and retrieval."""
    found: dict[str, dict[str, Any]] = {}

    def add(tid: str, conf: int, rationale: str) -> None:
        tid = tid.strip().upper()
        if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
            return
        if tid in found:
            found[tid]["confidence"] = max(found[tid]["confidence"], conf)
            if rationale not in found[tid]["rationale"]:
                found[tid]["rationale"] += f" {rationale}"
            return
        doc = kb_data.by_id(tid)
        found[tid] = {
            "id": tid,
            "name": doc["title"] if doc else "",
            "tactic": doc.get("tactic", "") if doc else "",
            "confidence": conf,
            "rationale": rationale,
            "detection_queries": (doc.get("queries", []) if doc else []),
            "remediation": (doc.get("remediation", []) if doc else []),
        }

    explicit = alert.get("mitre_technique")
    if explicit:
        for tid in re.findall(r"T\d{4}(?:\.\d{3})?", str(explicit)):
            add(tid, 92, "Vendor-supplied ATT&CK mapping on the alert.")

    for s in signals:
        add(s["technique"], min(95, 45 + s["weight"]), f"Behavioural signal: {s['label']}.")

    for d in docs:
        if d["kind"] != "technique":
            continue
        base = min(70, int(d["score"]))
        rationale = f"Knowledge-base match (BM25 {d['score']}) on alert text and indicators."
        tids = re.findall(r"T\d{4}(?:\.\d{3})?", d["title"] + " " + d.get("body", "")[:200])
        for tid in tids[:2]:
            add(tid, base, rationale)

    ranked = sorted(found.values(), key=lambda t: t["confidence"], reverse=True)[:8]
    return ranked


def score_risk(alert: dict, signals: list[dict], intel: list[dict],
               techniques: list[dict], ioc_total: int) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []
    score = 0

    sev = normalise_severity(alert.get("severity"))
    sev_pts = {"Informational": 0, "Low": 8, "Medium": 16, "High": 24, "Critical": 32}[sev]
    score += sev_pts
    factors.append({"name": "Alert severity", "points": sev_pts, "max": 32, "detail": sev})

    sig_pts = min(30, sum(s["weight"] for s in signals))
    score += sig_pts
    if signals:
        factors.append({"name": "Behavioural signals", "points": sig_pts, "max": 30,
                        "detail": ", ".join(s["label"] for s in signals[:4])})

    mal = [v for v in intel if v.get("reputation") == "malicious"]
    votes = max((v.get("malicious_votes", 0) for v in mal), default=0)
    if votes:
        intel_pts = min(25, 8 + votes * 3)
        score += intel_pts
        factors.append({"name": "Threat intelligence", "points": intel_pts, "max": 25,
                        "detail": f"{len(mal)} malicious indicator(s), peak {votes} engines"})

    abuse = max((v.get("abuse_confidence") or 0 for v in mal), default=0)
    if abuse >= 70:
        score += 5
        factors.append({"name": "Abuse confidence", "points": 5, "max": 5, "detail": f"{abuse}%"})
    elif abuse:
        score += 2
        factors.append({"name": "Abuse confidence", "points": 2, "max": 5, "detail": f"{abuse}%"})

    if _is_critical_asset(alert):
        score += 10
        factors.append({"name": "Critical asset", "points": 10, "max": 10,
                        "detail": str(alert.get("endpoint_hostname") or "identified critical asset")})
    if _is_privileged(alert):
        score += 6
        factors.append({"name": "Privileged account", "points": 6, "max": 6,
                        "detail": str(alert.get("user_account"))})

    if ioc_total >= 3:
        pts = min(8, ioc_total * 2)
        score += pts
        factors.append({"name": "Indicator density", "points": pts, "max": 8,
                        "detail": f"{ioc_total} distinct indicators"})

    high_conf = [t for t in techniques if t["confidence"] >= 85]
    if high_conf:
        score += 5
        factors.append({"name": "High-confidence mapping", "points": 5, "max": 5,
                        "detail": ", ".join(t["id"] for t in high_conf[:3])})

    score = max(0, min(100, score))
    if score >= 80:
        derived = "Critical"
    elif score >= 60:
        derived = "High"
    elif score >= 35:
        derived = "Medium"
    elif score >= 15:
        derived = "Low"
    else:
        derived = "Informational"

    verdict, confidence, why = _decide_verdict(alert, signals, intel, score, ioc_total)
    escalate, reason, sla = _escalation(alert, signals, intel, score, techniques,
                                        verdict, confidence)

    return {
        "score": score,
        "severity": derived,
        "source_severity": sev,
        "verdict": verdict,
        "confidence": confidence,
        "factors": factors,
        "escalate": escalate,
        "escalate_reason": reason,
        "sla": sla,
        "verdict_rationale": why,
    }


def _decide_verdict(alert: dict, signals: list[dict], intel: list[dict],
                    score: int, ioc_total: int) -> tuple[str, int, str]:
    mal = [v for v in intel if v.get("reputation") == "malicious"]
    hard = [s for s in signals if s["weight"] >= 20]
    proc = str(alert.get("process_name") or "").lower()

    if hard and mal:
        return "true_positive", 90, (
            f"{len(hard)} high-conviction behaviour signal(s) co-occur with "
            f"{len(mal)} indicator(s) confirmed malicious by threat intelligence."
        )
    if hard:
        return "true_positive", 80, (
            f"{len(hard)} high-conviction behaviour signal(s) observed "
            f"({', '.join(s['label'] for s in hard[:3])}); no external confirmation needed."
        )
    if mal and score >= 45:
        return "true_positive", 78, (
            "Threat intelligence confirms malicious infrastructure and behavioural "
            "context raises the composite risk above the true-positive threshold."
        )
    if mal or score >= 55:
        return "suspicious", 60, (
            "Indicators or behaviour are anomalous but not independently confirmed "
            "malicious. Requires analyst verification before containment."
        )
    if proc and any(t in proc for t in ("chrome", "firefox", "outlook", "teams", "slack")):
        return "benign", 70, "Firing process matches an expected user application."
    if score < 20 and ioc_total == 0 and not signals:
        return "benign", 55, "No indicators, no behavioural signals, low composite risk."
    return "unknown", 40, "Insufficient evidence to classify as malicious or benign."


def _escalation(alert: dict, signals: list[dict], intel: list[dict], score: int,
                techniques: list[dict], verdict: str, confidence: int) -> tuple[bool, str, str]:
    tids = {t["id"] for t in techniques}
    labels = " ".join(s["label"].lower() for s in signals)
    reasons: list[str] = []

    if tids & {"T1486"} or "shadow copy" in labels or "recovery disabling" in labels:
        reasons.append("Ransomware or destructive behaviour observed (T1486).")
    if tids & {"T1003"} or "credential dump" in labels or "registry hive" in labels:
        reasons.append("Credential dumping observed (T1003) — all local credentials assumed exposed.")
    if _is_critical_asset(alert) and verdict == "true_positive":
        reasons.append(f"Critical asset involved: {alert.get('endpoint_hostname')}.")
    if _is_privileged(alert) and verdict in ("true_positive", "suspicious"):
        reasons.append(f"Privileged account involved: {alert.get('user_account')}.")
    if tids & {"T1567"}:
        reasons.append("Exfiltration-capable technique observed (T1567).")
    if any(v.get("reputation") == "malicious" and v.get("ioc_type") == "ip"
           and v.get("abuse_confidence", 0) >= 90 for v in intel):
        reasons.append("Source IP has ≥90% abuse confidence and is actively interacting with the estate.")

    if not reasons and verdict == "true_positive":
        reasons.append(
            f"True-positive verdict at {confidence}% confidence with composite risk "
            f"{score}/100 — containment needs analyst confirmation."
        )
    if not reasons:
        return False, "", "T1 / 4h"

    sla = "P1 / 15m" if any(
        k in " ".join(reasons) for k in ("Ransomware", "Credential dumping", "Exfiltration")
    ) else "P2 / 1h"
    return True, " ".join(reasons), sla


def build_actions(alert: dict, signals: list[dict], intel: list[dict],
                  techniques: list[dict], risk: dict) -> list[dict[str, Any]]:
    """Containment plan mapped to the Tier-1 authority matrix."""
    host = alert.get("endpoint_hostname")
    user = alert.get("user_account")
    tids = {t["id"] for t in techniques}
    verdict = risk["verdict"]
    escalate = risk["escalate"]
    actions: list[dict[str, Any]] = []

    def add(action: str, priority: str, auto: bool, approval: bool, why: str) -> None:
        actions.append({
            "action": action, "priority": priority, "automated": auto,
            "requires_approval": approval, "rationale": why,
            "owner": "Automated" if auto else "Tier-1 Analyst",
            "status": "pending",
        })

    if verdict == "true_positive":
        if host:
            add(f"Isolate endpoint {host} via EDR", "P1", True, False,
                "Tier-1 is authorised to isolate on a confirmed true positive.")
        if user:
            add(f"Reset password and revoke sessions for {user}", "P1", True, False,
                "Authorised containment for a confirmed true positive.")
        add("Preserve memory image before any reboot", "P1", True, False,
            "Rebuilding destroys volatile evidence.")
    elif verdict == "suspicious":
        if host:
            add(f"Monitor {host} for 30 minutes and re-run enrichment", "P3", True, False,
                "Read-only monitoring is within authority while corroborating.")
        if user:
            add(f"Verify {user} activity against their manager's expected activity", "P3", True, False,
                "Needed to separate compromise from legitimate use.")
    else:
        add("Enrich indicators and review related alerts across the estate", "P3", True, False,
            "No containment warranted without corroboration.")

    for v in intel:
        if v.get("reputation") == "malicious" and v.get("ioc_type") in ("ip", "domain"):
            add(f"Block {v['indicator']} at proxy, DNS and firewall", "P1", True, False,
                f"Confirmed malicious: {v.get('malicious_votes', 0)} engines / "
                f"OTX pulses {v.get('pulse_count', 0)}.")

    labels = " ".join(s["label"].lower() for s in signals)
    if "shadow copy" in labels or tids & {"T1486"}:
        add("Verify offline/immutable backup integrity and restore-test before any RTO claim",
            "P1", False, False, "Backups are the recovery path in a ransomware event.")
        add("Disable the compromised identity estate-wide", "P1", False, True,
            "Multi-account disablement requires named-human approval.")
    if tids & {"T1003"}:
        add("Reset krbtgt twice to invalidate all Kerberos tickets", "P1", False, True,
            "Domain-wide impact — requires named-human approval.")
    if tids & {"T1003"} or "credential dump" in labels:
        add("Hunt for the dumping tool hash across all endpoints", "P2", True, False,
            "Establishes blast radius.")

    hashes = [v["indicator"] for v in intel
              if v.get("ioc_type") == "hash" and v.get("reputation") == "malicious"]
    if hashes:
        add(f"Block confirmed-malicious file hash(es) {', '.join(hashes[:3])} endpoint-wide", "P2", True, False,
            "Known-bad file hashes are high-confidence, low-risk blocks.")

    if escalate:
        add(f"Escalate to Tier-2 ({risk['sla']})", "P1", True, False, risk["escalate_reason"])
        add(f"Produce Tier-1 handoff package per PO-HANDOFF", "P2", True, False,
            "Handoff standard requires evidence location, ruled-out items and next actions.")
    else:
        add("Record rule-tuning recommendation for the detection owner", "P4", True, False,
            "Per PO-FP, every benign or low-risk close carries a tuning note.")

    if not any(t["id"] in tids for t in techniques) or not techniques:
        add("Validate ATT&CK mapping with vendor rule documentation", "P3", True, False,
            "No high-confidence technique mapping was derived.")
    return actions[:14]


def build_timeline(alert: dict, signals: list[dict]) -> list[dict[str, str]]:
    tl: list[dict[str, str]] = []
    if alert.get("timestamp"):
        tl.append({"time": str(alert["timestamp"]), "event": "Alert generated by source system"})
    if alert.get("process_name"):
        tl.append({"time": "observed", "event": f"Process: {alert['process_name']}"})
    if alert.get("command_line"):
        tl.append({"time": "observed", "event": f"Command line: {str(alert['command_line'])[:180]}"})
    for s in signals[:5]:
        tl.append({"time": "observed", "event": f"{s['label']} — matched `{s['evidence'][:90]}`"})
    if alert.get("endpoint_hostname"):
        tl.append({"time": "observed", "event": f"Host: {alert['endpoint_hostname']}"})
    tl.append({"time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "event": "AEGIS automated triage completed"})
    return tl


# ── layer 2: agentic tools ───────────────────────────────────────

def build_tools(ctx: dict[str, Any]) -> list[Tool]:
    async def _ctx(_a: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in
                {"intel": ctx.get("intel", []), "iocs": ctx.get("iocs", {})}.items()}

    return [
        Tool("query_threat_intelligence",
             "Look up current reputation for an indicator (public IPv4, file hash, domain or CVE). "
             "Use this to confirm or refute an indicator rather than assuming.",
             {"type": "object", "properties": {
                 "indicator": {"type": "string", "description": "IPv4, file hash, domain or CVE id"},
                 "type": {"type": "string", "enum": ["ip", "hash", "domain", "cve", "url"]},
             }, "required": ["indicator", "type"]},
             lambda a: tools.enrich_one(a.get("type", "ip"), a["indicator"])),

        Tool("search_knowledge_base",
             "Search the internal knowledge base for playbooks, ATT&CK techniques, escalation "
             "policy and detection queries. Use it to find the correct procedure before "
             "recommending actions.",
             {"type": "object", "properties": {
                 "query": {"type": "string"},
                 "limit": {"type": "integer", "description": "1-8, default 4"},
             }, "required": ["query"]},
             lambda a: [{"id": d["id"], "kind": d["kind"], "title": d["title"],
                         "excerpt": d["excerpt"]}
                        for d in rag.retrieve(a["query"], limit=int(a.get("limit", 4)))],
             ),

        Tool("lookup_technique",
             "Get the full ATT&CK record for a technique: description, triage steps, detection "
             "queries and remediation.",
             {"type": "object", "properties": {"id": {"type": "string", "description": "e.g. T1059.001"}},
              "required": ["id"]},
             lambda a: kb_data.by_id(a["id"]) or {"error": "technique not in local knowledge base"}),

        Tool("decode_payload",
             "Decode a base64 or base64-UTF16 blob taken from a command line, such as a "
             "PowerShell -EncodedCommand argument. Use this to establish what actually ran.",
             {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]},
             lambda a: {"decoded": decode_payload(a["value"])}),

        Tool("read_policy",
             "Read the authoritative internal policy. Required before deciding escalation or "
             "whether a containment action is authorised automatically.",
             {"type": "object", "properties": {"id": {"type": "string",
                                                       "description": "PO-ESCALATION, PO-CONTAINMENT, PO-HANDOFF or PO-FP"}},
              "required": ["id"]},
             lambda a: kb_data.by_id(a["id"]) or {"error": "unknown policy id"}),

        Tool("get_enrichment_context",
             "Return the enrichment already gathered during automated triage, so you do not "
             "re-query sources already consulted.",
             {"type": "object", "properties": {}},
             _ctx),
    ]


SYSTEM_PROMPT = ASSESSMENT_PROMPT + """

Operating rules:
1. Call read_policy('PO-ESCALATION') and read_policy('PO-CONTAINMENT') before finalising
   escalation and the action list. Do not guess the authority boundaries.
2. Use query_threat_intelligence only for indicators not already covered by
   get_enrichment_context.
3. Use decode_payload on any base64-looking command-line argument.
4. Prefer search_knowledge_base over guessing at procedure.
5. If no evidence supports malicious activity, a 'benign' or 'unknown' verdict is correct and
   preferred over inflating severity.
6. Attack-chain phases must follow ATT&CK kill-chain order and only include phases with evidence."""


def build_context(alert: dict, iocs: dict, intel: list[dict], signals: list[dict],
                  techniques: list[dict], risk: dict, docs: list[dict]) -> str:
    return json_dumps({
        "alert": {k: v for k, v in alert.items() if v},
        "extracted_indicators": iocs,
        "threat_intelligence": [{k: v for k, v in i.items() if k != "detail"} for i in intel],
        "behavioural_signals": signals,
        "attck_mapping": [{"id": t["id"], "name": t["name"], "confidence": t["confidence"]}
                          for t in techniques],
        "automated_risk_assessment": {k: v for k, v in risk.items() if k != "factors"},
        "knowledge_base_context": [{"id": d["id"], "title": d["title"], "excerpt": d["excerpt"]}
                                   for d in docs],
    })[:14000]


def json_dumps(obj: Any) -> str:
    import json

    return json.dumps(obj, default=str, indent=1)


# ── orchestration ────────────────────────────────────────────────

async def investigate(
    alert: dict[str, Any],
    use_llm: bool = True,
    on_event: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    t0 = datetime.now(timezone.utc)
    emit = on_event or (lambda _e: None)

    def emit_step(kind: str, **kw: Any) -> None:
        emit({"type": "step", "step": kind, "at": _now(), **kw})

    alert = dict(alert)
    incident_id = alert.get("incident_id") or _new_id()

    emit_step("extracting", message="Extracting indicators from alert payload")
    raw_text = json_dumps(alert)
    iocs = tools.merge_from_alert(alert)
    decode_note = ""
    if iocs.get("encoded"):
        decode_note = decode_payload(iocs["encoded"][0])

    signals = detect_signals(alert, raw_text)
    emit_step("signals", message=f"Detected {len(signals)} behavioural signal(s)", signals=signals)

    emit_step("retrieving", message="Retrieving knowledge base context")
    docs = rag.retrieve_for_alert(alert, iocs, limit=5)

    priority = tools.prioritise(iocs, settings.max_ioc_enrich)
    intel: list[dict[str, Any]] = []
    if priority:
        emit_step("enriching", message=f"Enriching {len(priority)} indicator(s) via threat intelligence",
                  indicators=[p["value"] for p in priority])
        intel = await tools.enrich_many(priority)
    else:
        emit_step("enriching", message="No indicators to enrich")

    ioc_total = sum(
        len(v) for v in iocs.values() if isinstance(v, list)
    )
    techniques = map_techniques(alert, raw_text, signals, docs)
    risk = score_risk(alert, signals, intel, techniques, ioc_total)
    actions = build_actions(alert, signals, intel, techniques, risk)
    timeline = build_timeline(alert, signals)

    result: dict[str, Any] = {
        "incident_id": incident_id,
        "created_at": _now(),
        "engine": "deterministic",
        "llm_used": False,
        "alert": alert,
        "verdict": risk["verdict"],
        "severity": risk["severity"],
        "confidence": risk["confidence"],
        "risk": {k: v for k, v in risk.items() if k != "verdict_rationale"} | {
            "verdict_rationale": risk["verdict_rationale"]},
        "summary": _deterministic_summary(alert, risk, signals, intel, techniques, decode_note),
        "narrative": "",
        "attack_chain": _chain_from_signals(signals, alert),
        "techniques": techniques,
        "iocs": {
            "ips": iocs.get("ips", []), "domains": iocs.get("domains", []),
            "urls": iocs.get("urls", []), "hashes": {"sha256_or_other": iocs.get("hashes", [])},
            "emails": iocs.get("emails", []), "cves": iocs.get("cves", []),
        },
        "intel": intel,
        "knowledge": [{k: d[k] for k in ("id", "kind", "title", "score", "excerpt")} for d in docs],
        "actions": actions,
        "timeline": timeline,
        "escalation": {
            "required": risk["escalate"], "reason": risk["escalate_reason"],
            "sla": risk["sla"],
        },
        "tool_trace": [],
        "analyst_notes": "",
        "duration_ms": 0,
    }

    if not use_llm:
        result["duration_ms"] = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
        return result

    # ── agentic layer ──
    emit_step("reasoning", message="Tier-2 model reasoning with tool access")
    router = Router()
    ctx = {"intel": [{k: v for k, v in i.items() if k != "detail"} for i in intel], "iocs": iocs}
    tool_list = build_tools(ctx)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Triage this alert:\n\n" + build_context(
            alert, iocs, intel, signals, techniques, risk, docs)},
    ]
    trace = result["tool_trace"]

    try:
        for round_no in range(1, settings.max_tool_rounds + 1):
            turn = await router.turn(messages, [t.spec() for t in tool_list],
                                     max_tokens=4096, temperature=0.15)
            messages.append({"role": "assistant", "content": turn.text, "tool_calls": turn.tool_calls})
            if not turn.tool_calls:
                break

            emit_step("tool_call", message=f"Model invoked {len(turn.tool_calls)} tool(s)",
                      tools=[c["name"] for c in turn.tool_calls])
            by_name = {t.name: t for t in tool_list}
            for call in turn.tool_calls:
                name = call["name"]
                tool = by_name.get(name)
                if not tool:
                    messages.append({"role": "tool", "name": name, "id": call.get("id", "call_0"),
                                     "content": {"error": f"unknown tool {name}"}})
                    continue
                started = datetime.now(timezone.utc)
                try:
                    res = await asyncio.wait_for(tool.handler(call.get("arguments", {})), timeout=45)
                    ok = True
                    summary = _summarise_tool(name, res)
                except Exception as e:
                    res, ok = {"error": f"{type(e).__name__}: {e}"}, False
                    summary = res["error"]
                msgs = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
                trace.append({"round": round_no, "name": name,
                              "arguments": call.get("arguments", {}),
                              "result_summary": summary[:400], "ok": ok, "duration_ms": msgs})
                emit_step("tool_result", tool=name, ok=ok, summary=summary[:200], duration_ms=msgs)
                messages.append({"role": "tool", "name": name, "id": call.get("id", "call_0"),
                                 "content": _trim(res)})

        final = parse_json_loose(turn.text)
        if not final:
            # The response was truncated (or refused the JSON contract). One cheap
            # retry, replacing the failed assistant turn with an explicit nudge.
            retry_msgs = messages[:-1] + [
                {"role": "user", "content":
                 "Return the final JSON assessment now. Output the JSON object only, "
                 "with no prose and no code fences. Keep narrative under 800 characters."}
            ]
            turn = await router.turn(retry_msgs, None, max_tokens=1500, temperature=0.1)
            final = parse_json_loose(turn.text)
        if not final and turn.text:
            emit_step("llm_unparseable", message="Model output was not valid JSON",
                      raw_excerpt=turn.text[:200])
        applied = _merge_llm(final, result, risk, actions, techniques)
        if applied:
            result.update(applied)
            result["engine"] = f"deterministic+{router.last_used}"
            result["llm_used"] = True
            emit_step("complete", message=f"Model assessment merged via {router.last_used}")
        else:
            emit_step("complete", message="Model returned unparseable output; kept deterministic result")
    except LLMError as e:
        result["engine"] = "deterministic"
        emit_step("llm_unavailable", message=f"LLM layer unavailable: {e}")
    except Exception as e:  # never let the model layer break the report
        result["engine"] = "deterministic"
        emit_step("llm_error", message=f"LLM layer error: {type(e).__name__}: {e}")

    result["tool_trace"] = trace
    result["duration_ms"] = int((datetime.now(timezone.utc) - t0).total_seconds() * 1000)
    return result


def _trim(obj: Any, limit: int = 6000) -> Any:
    s = json_dumps(obj)
    return obj if len(s) <= limit else s[:limit] + "…[truncated]"


def _summarise_tool(name: str, res: Any) -> str:
    if isinstance(res, dict):
        if name == "query_threat_intelligence":
            return (f"{res.get('indicator')}: {res.get('reputation')} "
                    f"({res.get('malicious_votes', 0)}/{res.get('total_engines', 0)} engines, "
                    f"sources={','.join(res.get('sources', [])) or 'none'})")
        if name == "lookup_technique":
            return f"{res.get('id', '?')} {res.get('title', '')}".strip() or str(res)[:160]
        if name == "decode_payload":
            return str(res.get("decoded", ""))[:300]
        if name == "read_policy":
            return f"{res.get('id', '?')} {res.get('title', '')}".strip() or str(res)[:160]
        if name == "search_knowledge_base":
            if isinstance(res, list):
                return ", ".join(f"{d.get('id')}" for d in res[:6]) or "no matches"
        return json_dumps(res)[:300]
    if isinstance(res, list):
        return f"{len(res)} result(s): " + ", ".join(str(d.get("id", "")) for d in res[:6] if isinstance(d, dict))
    return str(res)[:300]


def _merge_llm(llm: dict, result: dict, risk: dict, actions: list[dict],
               techniques: list[dict]) -> dict[str, Any]:
    if not llm or not isinstance(llm, dict):
        return {}
    out: dict[str, Any] = {}

    v = str(llm.get("verdict") or "").lower()
    if v in ("true_positive", "suspicious", "benign", "unknown"):
        out["verdict"] = v
    s = llm.get("severity")
    if s in SEVERITY_ORDER:
        out["severity"] = s
    c = llm.get("confidence")
    if isinstance(c, (int, float)):
        out["confidence"] = max(0, min(100, int(c)))

    if llm.get("summary"):
        out["summary"] = str(llm["summary"])[:2000]
    if llm.get("narrative"):
        out["narrative"] = str(llm["narrative"])[:12000]
    if llm.get("analyst_notes"):
        out["analyst_notes"] = str(llm["analyst_notes"])[:4000]

    if isinstance(llm.get("attack_chain"), list) and llm["attack_chain"]:
        chain = []
        for item in llm["attack_chain"][:10]:
            if isinstance(item, dict):
                chain.append({"phase": str(item.get("phase", ""))[:80],
                              "detail": str(item.get("detail", ""))[:400]})
        if chain:
            out["attack_chain"] = chain

    if isinstance(llm.get("timeline"), list) and llm["timeline"]:
        tl = [{"time": str(i.get("time", ""))[:40], "event": str(i.get("event", ""))[:300]}
              for i in llm["timeline"] if isinstance(i, dict)][:14]
        if tl:
            out["timeline"] = tl

    if isinstance(llm.get("techniques"), list) and llm["techniques"]:
        merged = {t["id"]: t for t in techniques}
        for t in llm["techniques"]:
            if not isinstance(t, dict):
                continue
            tid = str(t.get("id", "")).upper()
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", tid):
                continue
            conf = t.get("confidence")
            conf = int(conf) if isinstance(conf, (int, float)) else 60
            doc = kb_data.by_id(tid)
            merged[tid] = {
                "id": tid, "name": doc["title"] if doc else "",
                "tactic": doc.get("tactic", "") if doc else "",
                "confidence": max(0, min(100, conf)),
                "rationale": str(t.get("rationale", ""))[:400],
                "detection_queries": doc.get("queries", []) if doc else [],
                "remediation": doc.get("remediation", []) if doc else [],
            }
        out["techniques"] = sorted(merged.values(), key=lambda x: x["confidence"], reverse=True)[:10]

    if isinstance(llm.get("actions"), list) and llm["actions"]:
        merged_actions = list(actions)
        existing = " ".join(a["action"].lower() for a in merged_actions)
        for a in llm["actions"]:
            if not isinstance(a, dict):
                continue
            text = str(a.get("action", "")).strip()
            if not text or text.lower() in existing:
                continue
            pr = str(a.get("priority", "P3")).upper()
            merged_actions.append({
                "action": text[:240], "priority": pr if pr in ("P1", "P2", "P3", "P4") else "P3",
                "automated": False, "requires_approval": True,
                "rationale": str(a.get("rationale", ""))[:300],
                "owner": "Tier-2 Analyst", "status": "pending",
            })
        out["actions"] = merged_actions[:18]

    esc = llm.get("escalation")
    if isinstance(esc, dict) and "required" in esc:
        req = bool(esc.get("required"))
        reason = str(esc.get("reason", ""))[:500] or risk["escalate_reason"]
        out["escalation"] = {
            "required": req or risk["escalate"],
            "reason": reason or risk["escalate_reason"],
            "sla": risk["sla"] if (req or risk["escalate"]) else "T1 / 4h",
        }
        out["risk"] = dict(result.get("risk", {})) | {
            "escalate": out["escalation"]["required"],
            "escalate_reason": out["escalation"]["reason"],
            "sla": out["escalation"]["sla"],
        }

    return out


def _deterministic_summary(alert: dict, risk: dict, signals: list[dict],
                           intel: list[dict], techniques: list[dict], decode_note: str) -> str:
    parts: list[str] = []
    host = alert.get("endpoint_hostname") or "the affected host"
    title = alert.get("title") or alert.get("rule_name") or "an unspecified detection"
    parts.append(f"{title} on {host}.")

    if signals:
        parts.append("Behavioural evidence: " + ", ".join(s["label"] for s in signals[:4]) + ".")
    if intel:
        queried = [v for v in intel if v.get("sources")]
        mal = [v for v in intel if v.get("reputation") == "malicious"]
        errored = [v for v in intel if v.get("error")]
        if mal:
            parts.append(tools.indicator_summary(intel))
        elif queried:
            parts.append(
                f"{len(queried)} indicator(s) checked against {', '.join(sorted({s for v in queried for s in v['sources']}))}; "
                "none returned a malicious reputation."
            )
        elif errored:
            parts.append(
                f"Enrichment failed for {len(errored)} indicator(s) "
                f"({errored[0]['error'][:120]}). Treat indicator reputation as unverified."
            )
        else:
            parts.append(
                "Threat-intelligence enrichment is not configured, so no indicator could be "
                "independently confirmed. Verdict rests on behavioural evidence alone — treat "
                "indicator reputation as unverified."
            )
    else:
        parts.append("No indicators were available for enrichment.")

    if techniques:
        parts.append("Mapped to " + ", ".join(
            f"{t['id']} ({t['name']})" for t in techniques[:3] if t["name"]
        ) + ".")
    parts.append(f"Composite risk {risk['score']}/100 — {risk['severity']}, "
                 f"verdict {risk['verdict'].replace('_', ' ')} at {risk['confidence']}% confidence.")
    if decode_note and "No decodable" not in decode_note:
        parts.append("A base64 command-line argument decoded to readable text; see indicators.")
    if risk["escalate"]:
        parts.append(f"ESCALATION REQUIRED ({risk['sla']}): {risk['escalate_reason']}")
    return " ".join(parts)


def _chain_from_signals(signals: list[dict], alert: dict) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    order = {
        "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
        "T1110": "Credential Access", "T1003": "Credential Access", "T1552": "Credential Access",
        "T1056": "Collection", "T1059.001": "Execution", "T1059.003": "Execution",
        "T1053": "Execution", "T1218": "Execution", "T1027": "Defense Evasion",
        "T1055": "Defense Evasion", "T1620": "Defense Evasion", "T1547": "Persistence",
        "T1021": "Lateral Movement", "T1071": "Command and Control", "T1567": "Exfiltration",
        "T1486": "Impact", "T1498": "Impact", "T1499": "Impact", "T1531": "Impact",
    }
    for tid, phase in order.items():
        for s in signals:
            if s["technique"] == tid:
                chain.append({"phase": phase, "detail": f"{s['label']} — `{s['evidence'][:140]}`"})
                break
    if not chain and alert.get("title"):
        chain.append({"phase": "Observed", "detail": str(alert["title"])[:240]})
    return chain
