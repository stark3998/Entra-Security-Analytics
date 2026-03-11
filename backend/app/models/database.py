"""SQLAlchemy models and database engine for the log analytics tool."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from app.config import get_settings


# ── Base ───────────────────────────────────────────────────────


class Base(DeclarativeBase):
    """Declarative base for all models."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ──────────────────────────────────────────────────────


class LogSource(str, enum.Enum):
    ENTRA_SIGNIN = "entra_signin"
    ENTRA_AUDIT = "entra_audit"
    OFFICE365 = "office365"
    SHAREPOINT = "sharepoint"
    POWERAPPS = "powerapps"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AlertChannel(str, enum.Enum):
    EMAIL = "email"
    TEAMS = "teams"
    SLACK = "slack"


class AlertDeliveryStatus(str, enum.Enum):
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"


# ── Log Models ─────────────────────────────────────────────────


class SignInLog(Base):
    """Microsoft Entra sign-in log entry."""

    __tablename__ = "sign_in_logs"

    id = Column(String, primary_key=True)  # Graph signIn.id
    user_id = Column(String, nullable=False, index=True)
    user_principal_name = Column(String, nullable=False, index=True)
    user_display_name = Column(String, default="")
    app_id = Column(String, default="")
    app_display_name = Column(String, default="")
    ip_address = Column(String, default="")
    client_app_used = Column(String, default="")
    is_interactive = Column(Boolean, default=True)
    resource_display_name = Column(String, default="")
    # Location
    location_city = Column(String, default="")
    location_state = Column(String, default="")
    location_country = Column(String, default="")
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    # Status
    status_error_code = Column(Integer, default=0)
    status_failure_reason = Column(String, default="")
    # Risk
    risk_level_during_sign_in = Column(String, default="none")
    risk_level_aggregated = Column(String, default="none")
    risk_state = Column(String, default="none")
    risk_detail = Column(String, default="")
    risk_event_types = Column(JSON, default=list)  # list[str]
    # Conditional access
    conditional_access_status = Column(String, default="notApplied")
    applied_ca_policies = Column(JSON, default=list)
    # MFA
    mfa_detail = Column(JSON, nullable=True)
    # Auth details
    authentication_details = Column(JSON, default=list)
    # Device
    device_id = Column(String, default="")
    device_os = Column(String, default="")
    device_browser = Column(String, default="")
    # Timestamps
    created_date_time = Column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at = Column(DateTime(timezone=True), default=utcnow)
    # Raw JSON for full fidelity
    raw_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_signin_user_time", "user_principal_name", "created_date_time"),
        Index("ix_signin_risk", "risk_level_during_sign_in"),
    )


class AuditLog(Base):
    """Microsoft Entra audit log entry."""

    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True)  # Graph directoryAudit.id
    activity_display_name = Column(String, nullable=False, index=True)
    activity_date_time = Column(DateTime(timezone=True), nullable=False, index=True)
    category = Column(String, default="", index=True)
    operation_type = Column(String, default="")
    result = Column(String, default="")
    result_reason = Column(String, default="")
    logged_by_service = Column(String, default="")
    correlation_id = Column(String, default="")
    # Initiated By
    initiated_by_user_id = Column(String, default="", index=True)
    initiated_by_user_upn = Column(String, default="", index=True)
    initiated_by_user_display_name = Column(String, default="")
    initiated_by_app_id = Column(String, default="")
    initiated_by_app_display_name = Column(String, default="")
    # Target resources (stored as JSON array)
    target_resources = Column(JSON, default=list)
    # Additional details
    additional_details = Column(JSON, default=list)
    ingested_at = Column(DateTime(timezone=True), default=utcnow)
    raw_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_audit_user_time", "initiated_by_user_upn", "activity_date_time"),
        Index("ix_audit_activity", "activity_display_name", "activity_date_time"),
    )


class O365ActivityLog(Base):
    """Unified model for Office 365, SharePoint, and Power Apps activity logs."""

    __tablename__ = "o365_activity_logs"

    id = Column(String, primary_key=True)  # O365 audit record Id
    record_type = Column(Integer, nullable=False)
    creation_time = Column(DateTime(timezone=True), nullable=False, index=True)
    operation = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=False, index=True)
    user_type = Column(Integer, default=0)
    client_ip = Column(String, default="")
    workload = Column(String, default="", index=True)
    result_status = Column(String, default="")
    object_id = Column(String, default="")
    source = Column(Enum(LogSource), nullable=False, index=True)
    # SharePoint-specific
    site_url = Column(String, default="")
    source_file_name = Column(String, default="")
    source_file_extension = Column(String, default="")
    source_relative_url = Column(String, default="")
    item_type = Column(String, default="")
    # Sharing-specific
    target_user_or_group_name = Column(String, default="")
    target_user_or_group_type = Column(String, default="")
    # Power Platform-specific
    app_name = Column(String, default="")
    environment_name = Column(String, default="")
    # General JSON for extended properties
    extended_properties = Column(JSON, default=dict)
    ingested_at = Column(DateTime(timezone=True), default=utcnow)
    raw_json = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_o365_user_time", "user_id", "creation_time"),
        Index("ix_o365_source_op", "source", "operation"),
    )


# ── Correlation Rule ───────────────────────────────────────────


class CorrelationRule(Base):
    """Defines a detection rule with trigger conditions and watch windows."""

    __tablename__ = "correlation_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    slug = Column(String, nullable=True, unique=True)  # URL-safe identifier
    name = Column(String, nullable=False, unique=True)
    description = Column(Text, default="")
    category = Column(String, default="", index=True)
    severity = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    risk_points = Column(Integer, default=10)
    watch_window_days = Column(Integer, default=0)
    rule_definition = Column(JSON, nullable=False)  # JSON DSL
    incident_on_trigger = Column(Boolean, default=False)
    is_system = Column(Boolean, default=True)  # System rules can't be deleted
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    incidents = relationship("Incident", back_populates="rule")
    watch_states = relationship("UserWatchState", back_populates="rule")


# ── User Watch State ───────────────────────────────────────────


class UserWatchState(Base):
    """Tracks elevated monitoring windows for users triggered by rules."""

    __tablename__ = "user_watch_states"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False, index=True)  # UPN
    rule_id = Column(Integer, ForeignKey("correlation_rules.id"), nullable=False)
    trigger_event_id = Column(String, nullable=False)
    trigger_event_source = Column(String, nullable=False)  # table name
    risk_contribution = Column(Integer, default=0)
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    rule = relationship("CorrelationRule", back_populates="watch_states")

    __table_args__ = (
        Index("ix_watch_user_active", "user_id", "is_active"),
        Index("ix_watch_window_end", "window_end"),
    )


# ── Incident ───────────────────────────────────────────────────


class Incident(Base):
    """Security incident created by correlation rules."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    severity = Column(Enum(Severity), nullable=False, default=Severity.MEDIUM)
    status = Column(
        Enum(IncidentStatus), nullable=False, default=IncidentStatus.OPEN, index=True
    )
    rule_id = Column(Integer, ForeignKey("correlation_rules.id"), nullable=True)
    user_id = Column(String, default="", index=True)  # Affected user UPN
    trigger_event_id = Column(String, default="")
    trigger_event_source = Column(String, default="")
    correlated_event_ids = Column(JSON, default=list)
    risk_score_at_creation = Column(Integer, default=0)
    assigned_to = Column(String, default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    rule = relationship("CorrelationRule", back_populates="incidents")
    alert_history = relationship("AlertHistoryEntry", back_populates="incident")


# ── Alert History ──────────────────────────────────────────────


class AlertHistoryEntry(Base):
    """Records alert delivery attempts for each incident."""

    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    channel = Column(Enum(AlertChannel), nullable=False)
    status = Column(Enum(AlertDeliveryStatus), nullable=False, default=AlertDeliveryStatus.SENT)
    error_message = Column(String, default="")
    sent_at = Column(DateTime(timezone=True), default=utcnow)

    incident = relationship("Incident", back_populates="alert_history")


# ── Collector State ────────────────────────────────────────────


class CollectorState(Base):
    """Tracks the last successful poll timestamp per collector."""

    __tablename__ = "collector_states"

    collector_name = Column(String, primary_key=True)
    last_successful_poll = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class AppSettings(Base):
    """Single-row table persisting runtime settings (auth mode, app registration)."""

    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, default=1)
    auth_mode = Column(String, nullable=False, default="client_credentials")
    azure_tenant_id = Column(String, default="")
    azure_client_id = Column(String, default="")
    azure_client_secret = Column(String, default="")  # plaintext v1; encrypt later
    frontend_client_id = Column(String, default="")
    jwt_audience = Column(String, default="")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


# ── Conditional Access Policy Models ──────────────────────────


class ConditionalAccessPolicy(Base):
    """A snapshot of an Entra ID Conditional Access policy."""

    __tablename__ = "conditional_access_policies"
    __table_args__ = (
        Index("ix_cap_state", "state"),
        Index("ix_cap_display_name", "display_name"),
    )

    id = Column(String, primary_key=True)  # Graph object id
    display_name = Column(String, nullable=False)
    state = Column(String, nullable=False)  # enabled / disabled / enabledForReportingButNotEnforced
    created_date_time = Column(DateTime(timezone=True), nullable=True)
    modified_date_time = Column(DateTime(timezone=True), nullable=True)
    conditions = Column(JSON, default=dict)
    grant_controls = Column(JSON, default=dict)
    session_controls = Column(JSON, default=dict)
    raw_json = Column(JSON, default=dict)
    synced_at = Column(DateTime(timezone=True), default=utcnow)

    coverage_entries = relationship(
        "PolicyCoverageCache",
        back_populates="policy",
        cascade="all, delete-orphan",
    )


class NamedLocation(Base):
    """Entra ID named / trusted location (IP-based or country-based)."""

    __tablename__ = "named_locations"

    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False)
    is_trusted = Column(Boolean, default=False)
    location_type = Column(String, nullable=False)  # ipRange | countryNamedLocation
    ip_ranges = Column(JSON, default=list)
    countries_and_regions = Column(JSON, default=list)
    include_unknown_countries = Column(Boolean, default=False)
    raw_json = Column(JSON, default=dict)
    synced_at = Column(DateTime(timezone=True), default=utcnow)


class AuthenticationStrength(Base):
    """Entra ID authentication strength policy."""

    __tablename__ = "authentication_strengths"

    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False)
    description = Column(Text, default="")
    policy_type = Column(String, default="")  # builtIn | custom
    requirements_satisfied = Column(String, default="")  # mfa | none
    allowed_combinations = Column(JSON, default=list)
    raw_json = Column(JSON, default=dict)
    synced_at = Column(DateTime(timezone=True), default=utcnow)


class DirectoryGroup(Base):
    """Cached Entra ID group or directory role used in CA policy targeting."""

    __tablename__ = "directory_groups"

    id = Column(String, primary_key=True)
    display_name = Column(String, nullable=False)
    object_type = Column(String, nullable=False)  # group | directoryRole
    description = Column(Text, default="")
    synced_at = Column(DateTime(timezone=True), default=utcnow)


class UserSignInProfile(Base):
    """Per-user historical sign-in profile for anomaly/risk detection."""

    __tablename__ = "user_signin_profiles"

    user_principal_name = Column(String, primary_key=True)
    user_display_name = Column(String, default="")
    user_id = Column(String, default="", index=True)
    # Historical aggregates stored as JSON
    known_locations = Column(JSON, default=list)       # [{city, state, country, lat, lon, first_seen, last_seen, count}]
    known_devices = Column(JSON, default=list)          # [{device_os, device_browser, device_id, first_seen, last_seen, count}]
    known_ips = Column(JSON, default=list)              # [{ip_address, first_seen, last_seen, count}]
    sign_in_hour_histogram = Column(JSON, default=list) # [count_hour_0, count_hour_1, ..., count_hour_23]
    total_sign_ins = Column(Integer, default=0)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    # Risk flags
    is_risky = Column(Boolean, default=False, index=True)
    risk_reasons = Column(JSON, default=list)  # ["new_location: Paris, FR", ...]
    risk_flagged_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class PolicyCoverageCache(Base):
    """Denormalized mapping: which users/groups/roles/apps each CA policy targets."""

    __tablename__ = "policy_coverage_cache"
    __table_args__ = (
        Index("ix_pcc_policy_entity", "policy_id", "entity_type"),
        Index("ix_pcc_entity", "entity_id", "entity_type"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    policy_id = Column(String, ForeignKey("conditional_access_policies.id", ondelete="CASCADE"), nullable=False)
    entity_type = Column(String, nullable=False)  # user | group | role | application | platform | location
    entity_id = Column(String, nullable=False)
    entity_display_name = Column(String, default="")
    inclusion_type = Column(String, nullable=False)  # include | exclude
    synced_at = Column(DateTime(timezone=True), default=utcnow)

    policy = relationship("ConditionalAccessPolicy", back_populates="coverage_entries")


# ── Engine & Session Factory ──────────────────────────────────


_engine = None
_session_factory: sessionmaker[Session] | None = None  # type: ignore[type-arg]


def get_engine(database_url: str | None = None) -> Any:
    """Create or return the cached SQLAlchemy engine."""
    global _engine  # noqa: PLW0603
    if _engine is None:
        url = database_url or get_settings().database_url
        connect_args = {}
        if url.startswith("sqlite"):
            connect_args["check_same_thread"] = False
        _engine = create_engine(url, connect_args=connect_args, echo=False)
    return _engine


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:  # type: ignore[type-arg]
    """Create or return the cached session factory."""
    global _session_factory  # noqa: PLW0603
    if _session_factory is None:
        engine = get_engine(database_url)
        _session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    return _session_factory


def get_db() -> Session:  # type: ignore[misc]
    """Dependency for FastAPI – yields a session and ensures cleanup."""
    factory = get_session_factory()
    session = factory()
    try:
        yield session  # type: ignore[misc]
    finally:
        session.close()


def init_db(database_url: str | None = None) -> None:
    """Create all tables (for development / first run)."""
    engine = get_engine(database_url)
    Base.metadata.create_all(bind=engine)


def reset_db_engine() -> None:
    """Reset cached engine and session factory (for tests)."""
    global _engine, _session_factory  # noqa: PLW0603
    if _engine:
        _engine.dispose()
    _engine = None
    _session_factory = None
