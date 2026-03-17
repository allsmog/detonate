"""Pydantic schemas for MITRE ATT&CK mapping endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class MITRETechniqueMatch(BaseModel):
    """A single MITRE ATT&CK technique match from analysis."""

    technique_id: str = Field(..., description="ATT&CK technique ID, e.g. T1059.004")
    name: str = Field(..., description="Technique name")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence score (0.0-1.0)"
    )
    evidence: str = Field("", description="Human-readable evidence summary")
    source: str = Field(
        "rule", description='Detection source: "rule" or "ai"'
    )


class MITREAnalysisResponse(BaseModel):
    """Response from MITRE ATT&CK mapping analysis."""

    techniques: list[MITRETechniqueMatch] = Field(
        default_factory=list,
        description="List of matched techniques",
    )
    tactics_coverage: dict[str, int] = Field(
        default_factory=dict,
        description="Count of matched techniques per tactic",
    )


class MITRETechniqueDetail(BaseModel):
    """Detailed information about a single MITRE ATT&CK technique."""

    technique_id: str
    name: str
    description: str
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    url: str = ""
