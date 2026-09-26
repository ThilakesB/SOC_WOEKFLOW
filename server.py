"""AEGIS — FastAPI application.

Routes are deliberately thin: orchestration lives in backend.analyst,
knowledge in backend.kb_data, retrieval in backend.rag.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend import analyst, kb_data, rag, samples, tools
from backend.config import settings
from backend.llm import Router
from backend.schemas import AlertIn, SearchRequest
from backend.store import (
    clear_investigations,
    get_investigation,
    incident_stats,
    init_db,
    list_alerts,
    list_investigations,
    mark_alert_processed,
    record_alert,
    save_investigation,
)

ROOT = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AEGIS — Autonomous SOC Analyst",
    description="Tier-1 security alert triage, enrichment, ATT&CK mapping and containment planning.",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── helpers ──────────────────────────────────────────────────────

def _clean(alert: dict) -> dict:
    return {k: v for k, v in alert.items() if v not in (None, "", [], {})}


async def _run(alert: dict, use_llm: bool) -> dict:
    result = await analyst.investigate(alert, use_llm=use_llm)
    save_investigation(result)
    return result


# ── health & capability discovery ────────────────────────────────

@app.get("/api/health")
async def health() -> dict[str, Any]:
    providers = await Router().health()
    return {
        "status": "operational",
        "version": app.version,
        "time": datetime.now(timezone.utc).isoformat(),
        "llm": providers,
        "llm_chain": settings.chain,
        "intel": settings.configured_intel(),
        "knowledge_base": rag.index_stats(),
    }


# ── investigation ────────────────────────────────────────────────

@app.post("/api/investigate")
async def investigate(
    payload: AlertIn,
    use_llm: bool = Query(True, description="Run the agentic Tier-2 reasoning layer"),
) -> dict[str, Any]:
    alert = _clean(payload.model_dump(exclude_none=True))
    if not alert:
        raise HTTPException(400, "Alert payload is empty.")
    result = await _run(alert, use_llm)
    return {"status": "success", "investigation": result}


@app.post("/api/investigate/stream")
async def investigate_stream(
    payload: AlertIn,
    use_llm: bool = Query(True),
) -> StreamingResponse:
    """Server-sent events: incremental pipeline progress, then the report."""
    alert = _clean(payload.model_dump(exclude_none=True))
    if not alert:
        raise HTTPException(400, "Alert payload is empty.")

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def emit(event: dict[str, Any]) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, event)

    async def produce() -> None:
        try:
            result = await analyst.investigate(alert, use_llm=use_llm, on_event=emit)
            save_investigation(result)
            await queue.put({"type": "result", "investigation": result})
        except Exception as e:
            await queue.put({"type": "error", "error": f"{type(e).__name__}: {e}"})
        finally:
            await queue.put({"type": "done"})

    async def reader() -> AsyncIterator[str]:
        task = asyncio.create_task(produce())
        try:
            while True:
                event = await queue.get()
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event["type"] == "done":
                    break
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(
        reader(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ── webhook ingestion ────────────────────────────────────────────

@app.post("/api/alerts/ingest")
async def ingest(
    request: Request,
    investigate_now: bool = Query(False, description="Run triage inline instead of queueing"),
) -> dict[str, Any]:
    """SIEM webhook. Accepts a single alert, a list, or a wrapped envelope."""
    try:
        body = await request.json()
    except Exception:
        raw = (await request.body()).decode("utf-8", "replace")
        body = {"raw_log": raw, "title": "Unparsed SIEM payload"}

    if isinstance(body, list):
        batch = body
    elif isinstance(body, dict) and isinstance(body.get("alerts"), list):
        batch = body["alerts"]
    elif isinstance(body, dict) and isinstance(body.get("events"), list):
        batch = body["events"]
    else:
        batch = [body]

    accepted: list[dict[str, Any]] = []
    for item in batch[:50]:
        if not isinstance(item, dict):
            item = {"raw_log": str(item), "title": "Unparsed SIEM payload"}
        alert_id = str(item.get("alert_id") or item.get("id") or uuid.uuid4().hex[:12])
        record_alert(alert_id, item, source="webhook")

        entry: dict[str, Any] = {"alert_id": alert_id, "investigation": None}
        if investigate_now:
            try:
                result = await _run({**item, "incident_id": None}, use_llm=True)
                mark_alert_processed(alert_id, result["incident_id"])
                entry["investigation"] = {
                    "incident_id": result["incident_id"],
                    "verdict": result["verdict"],
                    "severity": result["severity"],
                    "risk": result["risk"]["score"],
                    "escalate": result["escalation"]["required"],
                }
            except Exception as e:
                entry["error"] = f"{type(e).__name__}: {e}"
        accepted.append(entry)

    return {"status": "accepted", "count": len(accepted), "alerts": accepted}


@app.get("/api/alerts")
async def inbox(limit: int = Query(30, le=200)) -> dict[str, Any]:
    return {"status": "success", "alerts": list_alerts(limit)}


# ── incident history ─────────────────────────────────────────────

@app.get("/api/incidents")
async def incidents(
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return {
        "status": "success",
        "incidents": list_investigations(limit, offset),
        "stats": incident_stats(),
    }


@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: str) -> dict[str, Any]:
    inv = get_investigation(incident_id)
    if not inv:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return {"status": "success", "investigation": inv}


@app.delete("/api/incidents")
async def purge() -> dict[str, Any]:
    return {"status": "success", "removed": clear_investigations()}


# ── knowledge base / RAG ─────────────────────────────────────────

@app.get("/api/techniques")
async def techniques(tactic: str | None = None, q: str | None = None) -> dict[str, Any]:
    docs = [d for d in kb_data.TECHNIQUES]
    if tactic:
        docs = [d for d in docs if d.get("tactic", "").lower() == tactic.lower()]
    if q:
        hits = {h["id"] for h in rag.retrieve(q, limit=8, kinds=["technique"])}
        docs = [d for d in docs if d["id"] in hits]
    return {
        "status": "success",
        "tactics": sorted({d.get("tactic", "Unassigned") for d in kb_data.TECHNIQUES}),
        "techniques": [
            {
                "id": d["id"], "title": d["title"], "tactic": d.get("tactic", ""),
                "summary": d.get("body", "")[:280],
                "triage": d.get("triage", []),
                "queries": d.get("queries", []),
                "remediation": d.get("remediation", []),
            }
            for d in docs
        ],
    }


@app.get("/api/techniques/{technique_id}")
async def technique_detail(technique_id: str) -> dict[str, Any]:
    doc = kb_data.by_id(technique_id)
    if not doc:
        raise HTTPException(404, f"{technique_id} not in knowledge base")
    return {"status": "success", "technique": doc}


@app.post("/api/kb/search")
async def kb_search(req: SearchRequest) -> dict[str, Any]:
    hits = rag.retrieve(req.query, limit=max(1, min(req.limit, 20)), kinds=req.kinds)
    return {
        "status": "success",
        "results": [
            {"id": d["id"], "kind": d["kind"], "title": d["title"], "tactic": d.get("tactic", ""),
             "score": d["score"], "excerpt": d["excerpt"], "doc": d["doc"]}
            for d in hits
        ],
    }


# ── IOC utilities ────────────────────────────────────────────────

class ExtractReq(BaseModel):
    text: str = Field(min_length=1)


@app.post("/api/iocs/extract")
async def ioc_extract(req: ExtractReq) -> dict[str, Any]:
    found = tools.extract(req.text)
    total = sum(len(v) for v in found.values() if isinstance(v, list))
    return {
        "status": "success",
        "iocs": found,
        "total": total,
        "priority": tools.prioritise(found, settings.max_ioc_enrich),
    }


class EnrichReq(BaseModel):
    items: list[dict[str, str]] = Field(min_length=1, max_length=25)


@app.post("/api/iocs/enrich")
async def ioc_enrich(req: EnrichReq) -> dict[str, Any]:
    valid = {"ip", "hash", "domain", "cve", "url"}
    items = [i for i in req.items if i.get("type") in valid and i.get("value")]
    if not items:
        raise HTTPException(400, "No valid indicators. type must be one of ip/hash/domain/cve/url.")
    return {"status": "success", "results": await tools.enrich_many(items[:25])}


# ── samples ──────────────────────────────────────────────────────

@app.get("/api/samples")
async def sample_list() -> dict[str, Any]:
    return {
        "status": "success",
        "samples": [
            {"id": s["id"], "name": s["name"], "severity": s["severity"],
             "tactic": s["tactic"], "alert": s["alert"]}
            for s in samples.SAMPLES
        ],
    }


# ── static frontend (built SPA) ──────────────────────────────────
_dist = ROOT / "frontend" / "dist"
if _dist.exists():
    app.mount("/", StaticFiles(directory=str(_dist), html=True), name="spa")
