"""Runtime configuration. Single source of truth for keys, paths and tuning."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "aegis.db"


def _key(*names: str) -> str:
    for n in names:
        v = (os.getenv(n) or "").strip()
        if v:
            return v
    return ""


@dataclass(frozen=True)
class Settings:
    # ── LLM providers (ordered failover chain) ────────────────────
    gemini_key: str = field(default_factory=lambda: _key("GEMINI_API_KEY", "GOOGLE_API_KEY"))
    gemini_model: str = field(default_factory=lambda: _key("GEMINI_MODEL") or "gemini-2.0-flash")

    openrouter_key: str = field(default_factory=lambda: _key("OPENROUTER_API_KEY"))
    openrouter_model: str = field(
        default_factory=lambda: _key("OPENROUTER_MODEL") or "anthropic/claude-opus-4.5"
    )

    anthropic_key: str = field(default_factory=lambda: _key("ANTHROPIC_API_KEY"))

    ollama_host: str = field(default_factory=lambda: _key("OLLAMA_HOST") or "http://127.0.0.1:11434")
    ollama_model: str = field(default_factory=lambda: _key("OLLAMA_MODEL") or "qwen2.5:7b")

    # ── Enrichment sources ────────────────────────────────────────
    virustotal_key: str = field(default_factory=lambda: _key("VIRUSTOTAL_API_KEY"))
    abuseipdb_key: str = field(default_factory=lambda: _key("ABUSEIPDB_API_KEY"))
    otx_key: str = field(default_factory=lambda: _key("OTX_API_KEY", "ALIENVAULT_OTX_API_KEY"))
    shodan_key: str = field(default_factory=lambda: _key("SHODAN_API_KEY"))

    # ── Agent tuning ──────────────────────────────────────────────
    max_tool_rounds: int = int(os.getenv("MAX_TOOL_ROUNDS", "6"))
    agent_timeout: int = int(os.getenv("AGENT_TIMEOUT", "180"))
    enrichment_timeout: int = int(os.getenv("ENRICHMENT_TIMEOUT", "12"))
    max_ioc_enrich: int = int(os.getenv("MAX_IOC_ENRICH", "8"))
    store_history_limit: int = int(os.getenv("STORE_HISTORY_LIMIT", "500"))

    @property
    def chain(self) -> list[str]:
        """Provider failover order. First configured wins; all optional."""
        order = []
        if self.gemini_key:
            order.append("gemini")
        if self.anthropic_key and not self.openrouter_key:
            order.append("anthropic")
        elif self.openrouter_key:
            order.append("openrouter")
        if self.ollama_host:
            order.append("ollama")
        return order

    def configured_intel(self) -> dict[str, bool]:
        return {
            "virustotal": bool(self.virustotal_key),
            "abuseipdb": bool(self.abuseipdb_key),
            "otx": bool(self.otx_key),
            "shodan": bool(self.shodan_key),
            "nvd": True,  # public, no key required
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
