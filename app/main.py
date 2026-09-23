"""FastAPI application: network prefix policy analysis.

Endpoints
---------
POST   /api/analyze                    analyze a rule set (optionally persist)
GET    /api/analyses                   list saved analysis versions
GET    /api/analyses/diff              semantic effective-action diff of two versions
GET    /api/analyses/{id}              fetch one version with the full result
GET    /api/analyses/{id}/rules        query rules (filters: status/action/ip_version)
GET    /api/analyses/{id}/findings     query findings (filters: severity/behavioral_only)
GET    /api/analyses/{id}/export.json  download the result as a JSON file
GET    /health                         liveness probe
"""

from __future__ import annotations

import json
import re
from contextlib import asynccontextmanager
from hashlib import sha256
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import JSONResponse

from . import __version__
from .analyzer import ANALYZER_VERSION, ValidationError, analyze_rules, semantic_diff
from . import db
from .schemas import AnalyzeRequest

_ANALYSIS_ID_RE = re.compile(r"^an_[0-9a-f]{16}$")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    yield


app = FastAPI(
    title="Network Prefix Policy Analyzer",
    version=__version__,
    description=(
        "Submit IPv4/IPv6 CIDR rules with priority, action and source tags. "
        "The service computes each rule's effective coverage under longest-prefix "
        "match, identifies fully shadowed / partially overlapping / action-conflicting "
        "rules, and returns reproducible minimal conflict pairs."
    ),
    lifespan=lifespan,
)


@app.exception_handler(ValidationError)
async def _validation_error_handler(_request, exc: ValidationError):
    return JSONResponse(status_code=400, content={"error": "invalid_ruleset", "detail": str(exc)})


def _make_id(ruleset_hash: str) -> str:
    return "an_" + ruleset_hash[:16]


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "prefix-policy-analyzer",
        "version": __version__,
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__, "analyzer_version": ANALYZER_VERSION}


@app.post("/api/analyze", status_code=200)
def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    """Analyze a rule set.

    The analysis is deterministic: identical inputs always produce the same
    ``ruleset_hash`` and the same ``id`` (stored versions are deduplicated).
    """
    raw_rules = [r.model_dump(exclude_defaults=False) for r in req.rules]
    # model_dump turns unset rule_id into None; the analyzer assigns r1, r2...
    result = analyze_rules(raw_rules)

    analysis_id = _make_id(result["ruleset_hash"])
    persisted = False
    if req.save:
        saved_id = db.save_analysis(analysis_id, req.name, result)
        persisted = True
        analysis_id = saved_id

    result["id"] = analysis_id
    result["name"] = req.name
    result["created_at"] = db.utc_now_iso()
    result["persisted"] = persisted
    return result


@app.get("/api/analyses")
def list_analyses(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict[str, Any]:
    total, analyses = db.list_analyses(limit=limit, offset=offset)
    return {"total": total, "analyses": analyses}


@app.get("/api/analyses/diff")
def diff_analyses(
    base: str = Query(..., description="Base analysis version id"),
    target: str = Query(..., description="Target analysis version id"),
) -> dict[str, Any]:
    """Semantic diff of the effective forwarding actions of two saved versions.

    Each address resolves to ``permit``/``deny`` (the action of the longest
    matching winner rule) or ``none`` when no rule matches.  Only addresses
    covered by at least one version participate.  Changed address runs are
    returned as minimal CIDR ranges, merging adjacent ranges solely when their
    change type is identical.
    """
    for label, analysis_id in (("base", base), ("target", target)):
        if not _ANALYSIS_ID_RE.fullmatch(analysis_id):
            raise HTTPException(
                status_code=400,
                detail=f"invalid {label} analysis id {analysis_id!r}; expected 'an_' followed by 16 hex characters",
            )
    if base == target:
        raise HTTPException(
            status_code=400, detail="base and target must be different analysis versions"
        )

    base_result = db.get_analysis(base)
    if base_result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{base}' not found")
    target_result = db.get_analysis(target)
    if target_result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{target}' not found")

    return semantic_diff(base_result, target_result)


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str) -> dict[str, Any]:
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return result


@app.get("/api/analyses/{analysis_id}/rules")
def get_rules(
    analysis_id: str,
    status: str | None = Query(default=None, pattern="^(active|partial|shadowed)$"),
    action: str | None = Query(default=None, pattern="^(permit|deny)$"),
    ip_version: int | None = Query(default=None, alias="ip", ge=4, le=6),
) -> dict[str, Any]:
    rows = db.query_rules(
        analysis_id, status=status, action=action, ip_version=ip_version
    )
    if rows is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return {"analysis_id": analysis_id, "count": len(rows), "rules": rows}


@app.get("/api/analyses/{analysis_id}/findings")
def get_findings(
    analysis_id: str,
    severity: str | None = Query(default=None, pattern="^(conflict|warning|info)$"),
    behavioral_only: bool = Query(default=False),
) -> dict[str, Any]:
    rows = db.query_findings(
        analysis_id, severity=severity, behavioral_only=behavioral_only
    )
    if rows is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    return {"analysis_id": analysis_id, "count": len(rows), "findings": rows}


@app.get("/api/analyses/{analysis_id}/export.json")
def export_analysis(analysis_id: str) -> Response:
    result = db.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"analysis '{analysis_id}' not found")
    payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    return Response(
        content=payload,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{analysis_id}.json"'},
    )
