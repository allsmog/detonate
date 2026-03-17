from pydantic import BaseModel


class FeatureFlags(BaseModel):
    """Boolean flags indicating which features are enabled on this instance."""

    ai_enabled: bool
    yara_enabled: bool
    suricata_enabled: bool
    auth_enabled: bool
    screenshots_enabled: bool
    qemu_enabled: bool
    sandbox_pool_enabled: bool


class ProviderInfo(BaseModel):
    """Non-secret information about configured service providers."""

    ai_provider: str | None = None
    ai_model: str | None = None
    threat_intel_providers: list[dict[str, bool]] = []


class LimitsInfo(BaseModel):
    """Operational limits exposed for the UI."""

    max_file_size: int
    sandbox_pool_size: int
    sandbox_platform: str


class SettingsResponse(BaseModel):
    """Full sanitised settings response (admin-only)."""

    features: FeatureFlags
    providers: ProviderInfo
    limits: LimitsInfo
