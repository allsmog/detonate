from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "detonate"
    postgres_password: str = "detonate"
    postgres_db: str = "detonate"

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_url: str = "redis://localhost:6379/0"

    # MinIO
    minio_host: str = "localhost"
    minio_port: int = 9000
    minio_root_user: str = "detonate"
    minio_root_password: str = "detonatedev"
    minio_bucket: str = "samples"
    minio_secure: bool = False

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_cors_origins: list[str] = ["http://localhost:3000"]

    # File upload
    max_file_size: int = 268435456  # 256 MB

    # AI / LLM
    ai_enabled: bool = True
    llm_provider: str = "ollama"  # "ollama" or "anthropic"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    anthropic_api_key: SecretStr = SecretStr("")
    anthropic_model: str = "claude-sonnet-4-20250514"
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.3

    # Sandbox Machine Pool
    sandbox_pool_enabled: bool = False
    sandbox_pool_size: int = 3
    sandbox_platform: str = "linux"

    # YARA
    yara_enabled: bool = True
    yara_rules_path: str = "sandbox/yara/rules"

    # Auth / JWT
    auth_enabled: bool = False
    jwt_secret_key: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # Threat Intelligence
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")
    threat_intel_cache_ttl: int = 3600

    # Screenshots / Video
    screenshots_enabled: bool = False
    screenshots_interval: float = 1.0

    # QEMU / Windows Sandbox
    qemu_enabled: bool = False
    qemu_connection_uri: str = "qemu:///system"
    qemu_base_image: str = "detonate-windows"
    qemu_snapshot_name: str = "clean"
    qemu_guest_agent_port: int = 8080
    qemu_network: str = "default"

    # Suricata IDS
    suricata_enabled: bool = False
    suricata_image: str = "detonate-suricata"

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
