"""Pydantic models for the HTTP API (pydantic v2)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .analyzer import ValidationError, normalize_action


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cidr: str = Field(..., description="IPv4/IPv6 network in CIDR notation; host bits must be zero")
    action: str = Field(..., description="permit/allow or deny/block/drop/reject")
    priority: int = Field(
        default=100, ge=0, description="Smaller number = higher priority; only breaks same-CIDR ties"
    )
    source_tag: str = Field(default="default", description="Label of the rule's origin")
    rule_id: str | None = Field(default=None, description="Optional unique id; auto-generated as r1, r2...")

    @field_validator("action")
    @classmethod
    def _normalize_action(cls, v: str) -> str:
        try:
            return normalize_action(v)
        except ValidationError as exc:
            # Pydantic turns ValueError into a 422 validation error response.
            raise ValueError(str(exc)) from exc

    @field_validator("cidr", "source_tag")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("must not be empty")
        return v


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rules: list[RuleIn] = Field(..., min_length=1, description="Ordered rule set")
    name: str | None = Field(default=None, description="Optional human-readable version name")
    save: bool = Field(default=True, description="Persist this analysis as an immutable version")


class ListAnalysesResponse(BaseModel):
    total: int
    analyses: list[dict[str, Any]]


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
