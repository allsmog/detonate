"""Settings routes exposing runtime configuration (read-only)."""

import logging

from fastapi import APIRouter, Depends

from detonate.api.deps import get_current_user
from detonate.config import settings
from detonate.schemas.settings import (
    FeatureFlags,
    LimitsInfo,
    ProviderInfo,
    SettingsResponse,
)

logger = logging.getLogger("detonate.api.routes.settings")

router = APIRouter(tags=["settings"])


def _build_feature_flags() -> FeatureFlags:
    return FeatureFlags(
        ai_enabled=settings.ai_enabled,
        yara_enabled=settings.yara_enabled,
        suricata_enabled=settings.suricata_enabled,
        auth_enabled=settings.auth_enabled,
        screenshots_enabled=settings.screenshots_enabled,
        qemu_enabled=settings.qemu_enabled,
        sandbox_pool_enabled=settings.sandbox_pool_enabled,
    )


def _build_provider_info() -> ProviderInfo:
    # Import here to avoid circular imports and keep the service lazy-loaded
    from detonate.services.threat_intel.service import ThreatIntelService

    ti_service = ThreatIntelService()
    ti_statuses = ti_service.get_status()

    return ProviderInfo(
        ai_provider=settings.llm_provider if settings.ai_enabled else None,
        ai_model=(
            settings.ollama_model
            if settings.llm_provider == "ollama"
            else settings.anthropic_model
        )
        if settings.ai_enabled
        else None,
        threat_intel_providers=[
            {s["name"]: s["configured"]} for s in ti_statuses
        ],
    )


def _build_limits_info() -> LimitsInfo:
    return LimitsInfo(
        max_file_size=settings.max_file_size,
        sandbox_pool_size=settings.sandbox_pool_size,
        sandbox_platform=settings.sandbox_platform,
    )


@router.get("/settings/features", response_model=FeatureFlags)
async def get_feature_flags() -> FeatureFlags:
    """Return feature flags for the current instance.

    No authentication required -- the frontend needs this to toggle UI
    sections before the user logs in.
    """
    return _build_feature_flags()


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(
    _current_user=Depends(get_current_user),
) -> SettingsResponse:
    """Return the full sanitised runtime configuration.

    Requires authentication.  Secret values (API keys, passwords) are
    never exposed.
    """
    return SettingsResponse(
        features=_build_feature_flags(),
        providers=_build_provider_info(),
        limits=_build_limits_info(),
    )
