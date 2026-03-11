"""Application configuration loaded from environment variables (12-factor)."""

from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed, validated configuration sourced from .env / environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Azure / Entra ──────────────────────────────────────────────
    azure_tenant_id: str = Field(default="", description="Entra tenant (directory) ID")
    azure_client_id: str = Field(default="", description="App registration client ID")
    azure_client_secret: str = Field(default="", description="App registration client secret")

    # ── Auth mode ──────────────────────────────────────────────────
    auth_mode: str = Field(
        default="client_credentials",
        description="Authentication mode: client_credentials | interactive | both",
    )
    frontend_client_id: str = Field(
        default="",
        description="SPA app registration client ID for interactive auth",
    )
    jwt_audience: str = Field(
        default="",
        description="Expected JWT audience (e.g. api://<frontend_client_id>)",
    )

    # ── Database ───────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite:///./log_analytics.db",
        description="SQLAlchemy database URL",
    )

    # ── Alerting – Email ───────────────────────────────────────────
    smtp_host: str = Field(default="", description="SMTP server hostname")
    smtp_port: int = Field(default=587, description="SMTP server port")
    smtp_user: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(default="", description="SMTP password")
    smtp_use_tls: bool = Field(default=True, description="Use STARTTLS")
    alert_email_from: str = Field(default="", description="Sender address for alerts")
    alert_email_to: str = Field(default="", description="Comma-separated recipient addresses")

    # ── Alerting – Teams ───────────────────────────────────────────
    teams_webhook_url: str = Field(default="", description="Teams incoming webhook URL")

    # ── Alerting – Slack ───────────────────────────────────────────
    slack_webhook_url: str = Field(default="", description="Slack incoming webhook URL")

    # ── Scheduler ──────────────────────────────────────────────────
    poll_interval_minutes: int = Field(
        default=15, ge=1, le=1440, description="Polling interval in minutes"
    )

    # ── Application ────────────────────────────────────────────────
    log_level: str = Field(default="INFO", description="Python logging level")
    app_host: str = Field(default="0.0.0.0", description="FastAPI bind host")
    app_port: int = Field(default=8000, ge=1, le=65535, description="FastAPI bind port")
    cors_origins: str = Field(
        default="http://localhost:5173",
        description="Comma-separated CORS origins",
    )

    # ── Derived helpers ────────────────────────────────────────────

    @field_validator("auth_mode")
    @classmethod
    def _validate_auth_mode(cls, v: str) -> str:
        allowed = {"client_credentials", "interactive", "both"}
        lower = v.lower()
        if lower not in allowed:
            msg = f"auth_mode must be one of {allowed}, got '{v}'"
            raise ValueError(msg)
        return lower

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            msg = f"log_level must be one of {allowed}, got '{v}'"
            raise ValueError(msg)
        return upper

    @property
    def cors_origin_list(self) -> list[str]:
        """Split comma-separated CORS origins into a list."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def alert_email_recipients(self) -> list[str]:
        """Split comma-separated email recipients into a list."""
        return [e.strip() for e in self.alert_email_to.split(",") if e.strip()]

    @property
    def email_alerting_enabled(self) -> bool:
        return bool(self.smtp_host and self.alert_email_to)

    @property
    def teams_alerting_enabled(self) -> bool:
        return bool(self.teams_webhook_url)

    @property
    def slack_alerting_enabled(self) -> bool:
        return bool(self.slack_webhook_url)

    @property
    def client_credentials_configured(self) -> bool:
        """Return True when app-registration credentials are fully populated."""
        return bool(
            self.azure_tenant_id and self.azure_client_id and self.azure_client_secret
        )

    @property
    def interactive_auth_enabled(self) -> bool:
        return self.auth_mode in ("interactive", "both")

    @property
    def effective_frontend_client_id(self) -> str:
        """Client ID the SPA should use — falls back to azure_client_id."""
        return self.frontend_client_id or self.azure_client_id


# Module-level singleton – import this everywhere
_settings: Settings | None = None


def get_settings() -> Settings:
    """Return the cached settings singleton."""
    global _settings  # noqa: PLW0603
    if _settings is None:
        _settings = Settings()  # type: ignore[call-arg]
    return _settings


def reset_settings() -> None:
    """Reset cached settings (useful in tests)."""
    global _settings  # noqa: PLW0603
    _settings = None
