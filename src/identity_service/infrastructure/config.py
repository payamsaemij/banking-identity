from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, loaded from the environment (and `.env`).

    Required settings such as ``database_url`` have no default: the
    application fails fast at startup when they are missing. Real
    secrets belong in the deployment environment, never in source
    control; ``.env.example`` documents every key with placeholders.
    """

    # `.env` is shared with docker-compose.yml, which keeps deployment
    # keys such as POSTGRES_PASSWORD beside the application settings;
    # keys this service does not own are ignored rather than rejected.
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- core -----------------------------------------------------------
    environment: Literal["local", "test", "staging", "production"] = "local"
    service_name: str = "banking-identity"
    # Empty string (the default when the environment provides nothing) fails
    # validation at startup, so the service never boots without a database.
    database_url: str = Field(
        default="",
        min_length=1,
        description="PostgreSQL DSN, e.g. postgresql+psycopg://user:pass@host:5432/db",
    )

    # --- logging --------------------------------------------------------
    log_level: str = "INFO"
    log_format: Literal["json", "console"] = "json"

    # --- token lifetimes --------------------------------------------------
    email_verification_token_ttl_seconds: int = Field(default=24 * 3600, gt=0)
    password_reset_token_ttl_seconds: int = Field(default=3600, gt=0)
    session_ttl_seconds: int = Field(default=8 * 3600, gt=0)

    # --- email delivery ---------------------------------------------------
    email_sender: Literal["console", "smtp"] = "console"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_address: str = "no-reply@example.com"
    smtp_use_tls: bool = True
    public_base_url: str = "http://localhost:8000"
    email_verification_url_template: str = "{base_url}/verify-email?token={token}"
    password_reset_url_template: str = "{base_url}/reset-password?token={token}"

    # --- administrative access ---------------------------------------------
    # Guards the reactivation endpoint (service-to-service). When unset,
    # reactivation is disabled outright (every request is rejected).
    admin_api_key: str | None = None

    # --- rate limits (per instance, per client IP) -------------------------
    register_rate_limit_max: int = Field(default=5, gt=0)
    register_rate_limit_window_seconds: int = Field(default=3600, gt=0)
    login_rate_limit_max: int = Field(default=10, gt=0)
    login_rate_limit_window_seconds: int = Field(default=60, gt=0)
    resend_rate_limit_max: int = Field(default=3, gt=0)
    resend_rate_limit_window_seconds: int = Field(default=600, gt=0)
    password_reset_request_rate_limit_max: int = Field(default=5, gt=0)
    password_reset_request_rate_limit_window_seconds: int = Field(default=600, gt=0)

    # --- HTTP ---------------------------------------------------------------
    cors_origins: list[str] = Field(default_factory=list)


@lru_cache
def get_settings() -> Settings:
    """Process-wide settings singleton."""
    return Settings()
