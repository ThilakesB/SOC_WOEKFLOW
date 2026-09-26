"""IOC extraction, validation and threat-intelligence enrichment.

Extraction is pure-regex and provider-independent so it works with no keys.
Enrichment is async, cached, and degrades to `error` per-source rather than
failing the investigation.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import settings
from . import store

# ── extraction patterns ──────────────────────────────────────────

_PUBIP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_HASH = re.compile(r"\b[A-Fa-f0-9]{64}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{32}\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|shop|club|icu|cc|tk|co|uk|de|fr|nl|br|in|jp|au|us|ca)\b"
)
_URL = re.compile(r"\bhttps?://[^\s\"'<>\\)\]]{4,300}", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_B64ISH = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")

# Things that look like indicators but are never IOCs.
_NOISE_IP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "8.8.8.8", "1.1.1.1"}
_NOISE_HASH = {
    "0" * 32, "0" * 40, "0" * 64, "f" * 32, "f" * 40, "f" * 64,
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "d41d8cd98f00b204e9800998ecf8427e",
}
_FILE_EXT = re.compile(r"\.(txt|log|json|xml|csv|htm|html|js|css|md|ya?ml|ini|cfg|conf|lock|pem|key)$", re.I)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _is_public(ip: str) -> bool:
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def extract(text: str) -> dict[str, list[str]]:
    """Extract indicators from arbitrary log or alert text."""
    text = text or ""
    out: dict[str, list[str]] = {
        "ips": [], "domains": [], "urls": [], "hashes": [], "emails": [], "cves": [], "encoded": []
    }

    for m in _URL.findall(text):
        u = m.rstrip(".,;:)]}\"'")
        out["urls"].append(u)
        try:
            host = urlparse(u).hostname
            if host and _DOMAIN.fullmatch(host):
                out["domains"].append(host)
        except ValueError:
            pass

    for ip in _PUBIP.findall(text):
        if ip in _NOISE_IP or not _is_public(ip):
            continue
        out["ips"].append(ip)

    for h in _HASH.findall(text):
        h = h.lower()
        if h in _NOISE_HASH or _FILE_EXT.search(text[max(0, text.find(h) - 1):text.find(h)]):
            continue
        out["hashes"].append(h)

    for d in _DOMAIN.findall(text):
        d = d.lower().strip(".")
        if d and not _is_public(d) and "." in d:
            out["domains"].append(d)

    out["emails"] = [e.lower() for e in _EMAIL.findall(text)]
    out["cves"] = [c.upper() for c in _CVE.findall(text)]
    out["encoded"] = [b for b in _B64ISH.findall(text) if len(b) >= 80][:5]

    for k in out:
        seen, uniq = set(), []
        for v in out[k]:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        out[k] = uniq
    return out


def merge_from_alert(alert: dict) -> dict[str, list[str]]:
    """Add structured fields present on the alert object to the free-text scan."""
    data = extract(json_dumps(alert))

    def add(bucket: str, value: Any) -> None:
        if not value:
            return
        v = str(value).strip()
        if v and v not in data[bucket]:
            data[bucket].append(v)

    add("ips", alert.get("source_ip"))
    add("ips", alert.get("dest_ip"))
    add("domains", alert.get("domain"))
    add("urls", alert.get("url"))
    add("emails", alert.get("email_sender"))

    for key, val in (alert.items() if isinstance(alert, dict) else []):
        if "hash" in str(key).lower() and val:
            add("hashes", val)

    return data


def json_dumps(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return str(obj)


def prioritise(data: dict[str, list[str]], limit: int) -> list[dict[str, str]]:
    """Order indicators for enrichment: most decision-relevant first."""
    ranked: list[dict[str, str]] = []
    for ip in data.get("ips", [])[:6]:
        ranked.append({"type": "ip", "value": ip})
    for h in data.get("hashes", [])[:6]:
        ranked.append({"type": "hash", "value": h})
    for d in data.get("domains", [])[:4]:
        ranked.append({"type": "domain", "value": d})
    for u in data.get("urls", [])[:4]:
        ranked.append({"type": "url", "value": u})
    for c in data.get("cves", [])[:4]:
        ranked.append({"type": "cve", "value": c})
    return ranked[:limit]


# ── enrichment ───────────────────────────────────────────────────

def _reputation(mal: int, susp: int, total: int) -> str:
    if total == 0:
        return "unknown"
    ratio = (mal + susp * 0.5) / total
    if mal == 0:
        return "harmless"
    if mal >= 8 or ratio >= 0.5:
        return "malicious"
    if mal >= 3 or ratio >= 0.2:
        return "suspicious"
    return "low_risk"


async def _vt_ip(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    if not settings.virustotal_key:
        return None
    r = await client.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": settings.virustotal_key},
    )
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    a = r.json().get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    mal, susp = st.get("malicious", 0), st.get("suspicious", 0)
    total = sum(st.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    return {
        "malicious_votes": mal,
        "suspicious_votes": susp,
        "total_engines": total,
        "reputation": _reputation(mal, susp, total),
        "country": a.get("country"),
        "as_owner": a.get("as_owner"),
        "isp": a.get("isp"),
        "source": "VirusTotal",
    }


async def _vt_hash(client: httpx.AsyncClient, h: str) -> dict[str, Any] | None:
    if not settings.virustotal_key:
        return None
    r = await client.get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        headers={"x-apikey": settings.virustotal_key},
    )
    if r.status_code == 404:
        return {"reputation": "unknown", "total_engines": 0, "malicious_votes": 0,
                "source": "VirusTotal", "error": "not found in VirusTotal"}
    if r.status_code != 200:
        return {"error": f"VT HTTP {r.status_code}"}
    a = r.json().get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    mal, susp = st.get("malicious", 0), st.get("suspicious", 0)
    total = sum(st.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    sig = a.get("signature_info") or {}
    return {
        "malicious_votes": mal,
        "suspicious_votes": susp,
        "total_engines": total,
        "reputation": _reputation(mal, susp, total),
        "malware_families": [sig["product"]] if sig.get("product") else [],
        "file_type": a.get("type_description"),
        "size": a.get("size"),
        "first_seen": (a.get("first_submission_date") or 0) / 1000 or None,
        "source": "VirusTotal",
    }


async def _abuse(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    if not settings.abuseipdb_key:
        return None
    r = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
    )
    if r.status_code != 200:
        return {"error": f"AbuseIPDB HTTP {r.status_code}"}
    d = r.json().get("data", {})
    return {
        "abuse_confidence": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "usage_type": d.get("usageType"),
        "source": "AbuseIPDB",
    }


async def _otx(client: httpx.AsyncClient, kind: str, value: str) -> dict[str, Any] | None:
    if not settings.otx_key:
        return None
    path = {"ip": "IPv4", "domain": "domain", "hash": "file"}[kind]
    r = await client.get(
        f"https://otx.alienvault.com/api/v1/indicators/{path}/{value}/general",
        headers={"X-OTX-API-KEY": settings.otx_key},
    )
    if r.status_code != 200:
        return {"error": f"OTX HTTP {r.status_code}"}
    d = r.json().get("indicator", "") or {}
    info = (r.json() or {}).get("pulse_info", {}) or {}
    mal = (info.get("malware_families") or [])
    if isinstance(mal, dict):
        mal = [k for k, v in mal.items() if v]
    return {
        "pulse_count": info.get("count", 0),
        "malware_families": (mal or [])[:5],
        "reputation": "malicious" if info.get("count", 0) > 0 else "unknown",
        "source": "AlienVault OTX",
    }


async def _shodan(client: httpx.AsyncClient, ip: str) -> dict[str, Any] | None:
    if not settings.shodan_key or not _is_public(ip):
        return None
    r = await client.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": settings.shodan_key})
    if r.status_code == 404:
        return {"reputation": "unknown", "source": "Shodan", "error": "no data"}
    if r.status_code != 200:
        return {"error": f"Shodan HTTP {r.status_code}"}
    d = r.json()
    return {
        "ports": d.get("ports", [])[:12],
        "hostnames": (d.get("hostnames") or [])[:6],
        "os": d.get("os"),
        "tags": d.get("tags", [])[:8],
        "reputation": "suspicious" if d.get("tags") else "unknown",
        "source": "Shodan",
    }


def kind_is_domain(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value))


async def _nvd(client: httpx.AsyncClient, cve: str) -> dict[str, Any] | None:
    r = await client.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": cve},
    )
    if r.status_code != 200:
        return {"error": f"NVD HTTP {r.status_code}"}
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return {"reputation": "unknown", "source": "NVD", "error": "no data"}
    c = vulns[0].get("cve", {})
    metrics = c.get("metrics", {})
    score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if arr:
            score = arr[0].get("cvssData", {}).get("baseScore")
            break
    desc = next(
        (d.get("value", "") for d in c.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    return {
        "cvss": score,
        "severity": _cvss_severity(score),
        "description": desc[:300],
        "published": c.get("published"),
        "reputation": "vulnerable",
        "source": "NVD",
    }


def _cvss_severity(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


async def enrich_one(kind: str, value: str) -> dict[str, Any]:
    """Enrich a single indicator across every configured source, in parallel."""
    cache_key = f"{kind}:{value.lower()}"
    cached = store.cache_get(cache_key)
    if cached:
        return {**cached, "cached": True}

    timeout = httpx.Timeout(settings.enrichment_timeout)
    limits = httpx.Limits(max_connections=8)
    out: dict[str, Any] = {
        "indicator": value,
        "ioc_type": kind,
        "malicious_votes": 0,
        "total_engines": 0,
        "abuse_confidence": None,
        "pulse_count": None,
        "reputation": "unknown",
        "sources": [],
        "malware_families": [],
        "detail": {},
    }
    errors: list[str] = []

    async with httpx.AsyncClient(timeout=timeout, limits=limits, follow_redirects=True) as client:
        if kind == "ip":
            jobs = [("virustotal", _vt_ip(client, value)), ("abuseipdb", _abuse(client, value)),
                    ("otx", _otx(client, "ip", value)), ("shodan", _shodan(client, value))]
        elif kind == "hash":
            jobs = [("virustotal", _vt_hash(client, value)), ("otx", _otx(client, "hash", value))]
        elif kind == "domain":
            jobs = [("otx", _otx(client, "domain", value))]
        elif kind == "cve":
            jobs = [("nvd", _nvd(client, value))]
        else:
            return {**out, "detail": {"note": f"no enrichment for {kind}"}}

        results = await asyncio.gather(*(c for _, c in jobs), return_exceptions=True)
        _REP_RANK = {"unknown": 0, "harmless": 1, "low_risk": 2, "suspicious": 3,
                     "vulnerable": 4, "malicious": 5}
        for (name, _), res in zip(jobs, results):
            if isinstance(res, BaseException):
                errors.append(f"{name}: {type(res).__name__}")
                continue
            if not res:
                continue
            out["sources"].append(name)
            out["detail"].update({k: v for k, v in res.items() if v is not None})
            if res.get("error"):
                errors.append(f"{name}: {res['error']}")
            rep = res.get("reputation")
            if rep and _REP_RANK.get(rep, 0) > _REP_RANK.get(out["reputation"], 0):
                out["reputation"] = rep
            if res.get("malicious_votes") is not None:
                out["malicious_votes"] = max(out["malicious_votes"], res.get("malicious_votes") or 0)
                out["total_engines"] = max(out["total_engines"], res.get("total_engines") or 0)
            if res.get("abuse_confidence") is not None:
                out["abuse_confidence"] = res["abuse_confidence"]
            if res.get("pulse_count") is not None:
                out["pulse_count"] = res["pulse_count"]
            if res.get("malware_families"):
                out["malware_families"] = list(
                    dict.fromkeys(out["malware_families"] + res["malware_families"])
                )[:6]

    if errors:
        out["detail"]["errors"] = errors

    # Only derive a reputation when no provider already supplied one.
    if out["reputation"] == "unknown":
        if out["malicious_votes"] or out["abuse_confidence"] or out["pulse_count"]:
            out["reputation"] = "malicious"
        elif out["total_engines"]:
            out["reputation"] = "harmless"

    if out["reputation"] != "unknown" or out["sources"]:
        store.cache_put(cache_key, out)
    return out


async def enrich_many(items: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Enrich with bounded concurrency to respect free-tier rate limits."""
    sem = asyncio.Semaphore(3)

    async def guarded(kind: str, value: str) -> dict[str, Any]:
        async with sem:
            try:
                return await enrich_one(kind, value)
            except Exception as e:  # never fail the investigation on enrichment
                return {"indicator": value, "ioc_type": kind, "reputation": "unknown",
                        "sources": [], "malware_families": [],
                        "error": f"{type(e).__name__}: {e}"}

    return await asyncio.gather(*(guarded(i["type"], i["value"]) for i in items))


def indicator_summary(verdicts: list[dict[str, Any]]) -> str:
    mal = [v for v in verdicts if v.get("reputation") == "malicious"]
    if not mal:
        return "No indicator returned a malicious reputation."
    bits = []
    for v in mal[:4]:
        votes = f"{v['malicious_votes']}/{v['total_engines']}" if v.get("total_engines") else ""
        bits.append(f"{v['indicator']} ({votes})".strip())
    return f"Malicious reputation: {', '.join(bits)}."
