"""MITRE ATT&CK analysis orchestrator.

Combines rule-engine matches with optional LLM-based classification,
deduplicates, and persists results on the Analysis record.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from detonate.models.analysis import Analysis
from detonate.prompts.mitre import build_behavioral_summary, build_mitre_prompt
from detonate.services.llm import BaseLLMProvider, LLMMessage
from detonate.services.mitre.data import load_techniques
from detonate.services.mitre.rules import evaluate_rules

logger = logging.getLogger("detonate.services.mitre.service")


def _build_tactics_coverage(techniques: list[dict]) -> dict[str, int]:
    """Build a mapping of tactic -> count of matched techniques.

    Uses the loaded ATT&CK data to resolve technique IDs to their
    associated tactics.
    """
    coverage: dict[str, int] = {}
    data = load_techniques()

    for tech in techniques:
        tid = tech.get("technique_id", "")
        info = data.get(tid)
        if info:
            for tactic in info.get("tactics", []):
                coverage[tactic] = coverage.get(tactic, 0) + 1
        else:
            # Fall back: check if the technique includes a tactic field
            for tactic in tech.get("tactics", []):
                coverage[tactic] = coverage.get(tactic, 0) + 1

    return coverage


def _parse_llm_techniques(raw_content: str) -> list[dict]:
    """Parse LLM response into a list of technique dicts.

    Handles common LLM output quirks: markdown fences, extra text
    before/after the JSON array, etc.
    """
    content = raw_content.strip()

    # Strip markdown code fences if present
    if content.startswith("```"):
        # Remove opening fence (possibly with language tag)
        first_newline = content.index("\n") if "\n" in content else 3
        content = content[first_newline + 1 :]
    if content.endswith("```"):
        content = content[:-3]
    content = content.strip()

    # Find the JSON array boundaries
    start = content.find("[")
    end = content.rfind("]")
    if start == -1 or end == -1 or end <= start:
        logger.warning("LLM response does not contain a JSON array")
        return []

    json_str = content[start : end + 1]

    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse LLM MITRE response: %s", exc)
        return []

    if not isinstance(parsed, list):
        return []

    results: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        tid = item.get("technique_id", "")
        if not tid:
            continue
        confidence = item.get("confidence", 0.5)
        if isinstance(confidence, str):
            try:
                confidence = float(confidence)
            except ValueError:
                confidence = 0.5
        confidence = max(0.0, min(1.0, float(confidence)))

        results.append({
            "technique_id": tid,
            "name": item.get("technique_name") or item.get("name", ""),
            "confidence": confidence,
            "evidence": item.get("evidence", ""),
            "source": "ai",
        })

    return results


def _merge_techniques(
    rule_matches: list[dict],
    ai_matches: list[dict],
) -> list[dict]:
    """Merge rule-engine and AI matches, preferring higher confidence."""
    merged: dict[str, dict] = {}

    for match in rule_matches:
        tid = match["technique_id"]
        merged[tid] = dict(match)

    for match in ai_matches:
        tid = match["technique_id"]
        if tid in merged:
            # Keep the entry with higher confidence; if AI is higher, merge
            existing = merged[tid]
            if match["confidence"] > existing["confidence"]:
                # Preserve both evidence descriptions
                combined_evidence = existing.get("evidence", "")
                ai_evidence = match.get("evidence", "")
                if combined_evidence and ai_evidence:
                    combined_evidence = f"{combined_evidence}; AI: {ai_evidence}"
                elif ai_evidence:
                    combined_evidence = ai_evidence

                merged[tid] = {
                    **match,
                    "evidence": combined_evidence,
                    "source": "rule+ai",
                }
            else:
                # AI confirmed but with lower confidence - note AI agreement
                ai_evidence = match.get("evidence", "")
                if ai_evidence and ai_evidence not in existing.get("evidence", ""):
                    existing["evidence"] = (
                        f"{existing.get('evidence', '')}; AI: {ai_evidence}"
                    )
                existing["source"] = "rule+ai"
        else:
            merged[tid] = dict(match)

    # Sort by confidence descending
    return sorted(merged.values(), key=lambda m: m["confidence"], reverse=True)


async def analyze_mitre(
    db: AsyncSession,
    analysis: Analysis,
    llm: BaseLLMProvider | None = None,
) -> list[dict]:
    """Run MITRE ATT&CK mapping on a completed analysis.

    1. Run the rule engine on ``analysis.result``.
    2. If an LLM provider is given, run AI classification.
    3. Merge and deduplicate (prefer higher confidence).
    4. Store on the analysis record as ``analysis.result["mitre_techniques"]``.
    5. Return the techniques list.

    Parameters
    ----------
    db:
        Active async database session.
    analysis:
        The Analysis ORM object (must have ``result`` populated).
    llm:
        Optional LLM provider for AI-enhanced classification.

    Returns
    -------
    list[dict]
        List of matched techniques.
    """
    result: dict[str, Any] = analysis.result or {}

    # 1. Rule engine
    rule_matches = evaluate_rules(result)
    logger.info(
        "Rule engine found %d techniques for analysis %s",
        len(rule_matches),
        analysis.id,
    )

    # 2. AI classification (optional)
    ai_matches: list[dict] = []
    if llm is not None:
        try:
            behavioral_summary = build_behavioral_summary(result)
            prompt = build_mitre_prompt(behavioral_summary, rule_matches)
            response = await llm.complete(
                messages=[LLMMessage(role="user", content=prompt)],
                system=(
                    "You are a malware analysis expert specializing in MITRE ATT&CK "
                    "framework mapping. Respond only with the requested JSON."
                ),
            )
            ai_matches = _parse_llm_techniques(response.content)
            logger.info(
                "LLM found %d techniques for analysis %s (model=%s)",
                len(ai_matches),
                analysis.id,
                response.model,
            )
        except Exception:
            logger.exception("LLM MITRE classification failed for analysis %s", analysis.id)

    # 3. Merge
    techniques = _merge_techniques(rule_matches, ai_matches)

    # 4. Persist
    # We store MITRE results inside the existing result JSONB column
    updated_result = dict(result)
    updated_result["mitre_techniques"] = techniques
    updated_result["mitre_tactics_coverage"] = _build_tactics_coverage(techniques)
    analysis.result = updated_result
    await db.flush()

    logger.info(
        "MITRE mapping complete for analysis %s: %d techniques",
        analysis.id,
        len(techniques),
    )

    return techniques
