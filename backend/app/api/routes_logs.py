"""Log query endpoints — sign-in, audit, O365 activity logs."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models.database import (
    AuditLog,
    LogSource,
    O365ActivityLog,
    SignInLog,
    get_db,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["logs"])


# ── Sync status tracking ─────────────────────────────────────────────────

_sync_status: dict = {
    "state": "idle",          # idle | running | completed | failed
    "started_at": None,
    "completed_at": None,
    "entries": [],             # list of {timestamp, level, message}
}

_MAX_LOG_ENTRIES = 200


class _SyncLogHandler(logging.Handler):
    """Custom handler that captures log records into the sync status entries."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "message": self.format(record),
            }
            if len(_sync_status["entries"]) < _MAX_LOG_ENTRIES:
                _sync_status["entries"].append(entry)
        except Exception:
            pass  # never break the logger


@router.post("/sync")
async def sync_logs():
    """Trigger an immediate log-collection cycle for all collectors."""
    if _sync_status["state"] == "running":
        return {"status": "already_running", "message": "A sync is already in progress."}

    async def _run():
        # Set up the capture handler on the relevant loggers
        handler = _SyncLogHandler()
        handler.setFormatter(logging.Formatter("%(name)s — %(message)s"))
        handler.setLevel(logging.DEBUG)

        # Attach to app loggers that produce collection output
        captured_loggers = [
            logging.getLogger("app.scheduler.polling"),
            logging.getLogger("app.collectors"),
            logging.getLogger("app.collectors.base"),
            logging.getLogger("app.collectors.entra_signin"),
            logging.getLogger("app.collectors.entra_audit"),
            logging.getLogger("app.collectors.office365"),
            logging.getLogger("app.collectors.sharepoint"),
            logging.getLogger("app.collectors.powerapps"),
            logging.getLogger("app.auth.msal_client"),
            logging.getLogger("app.analyzers.rules_engine"),
            logging.getLogger("app.analyzers.anomaly"),
            logging.getLogger("app.analyzers.user_profiles"),
            logging.getLogger("app.alerting.dispatcher"),
        ]
        saved_levels = {}
        for lg in captured_loggers:
            lg.addHandler(handler)
            saved_levels[lg.name] = lg.level
            lg.setLevel(logging.DEBUG)

        _sync_status.update(
            state="running",
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=None,
            entries=[{
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "INFO",
                "message": "Sync started — running all collectors…",
            }],
        )

        try:
            from app.scheduler.polling import run_collection_cycle
            await run_collection_cycle()
            _sync_status["state"] = "completed"
            _sync_status["entries"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "INFO",
                "message": "Sync completed successfully.",
            })
        except Exception as exc:
            _sync_status["state"] = "failed"
            _sync_status["entries"].append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": "ERROR",
                "message": f"Sync failed: {exc}",
            })
            logger.exception("Manual sync failed")
        finally:
            _sync_status["completed_at"] = datetime.now(timezone.utc).isoformat()
            for lg in captured_loggers:
                lg.removeHandler(handler)
                lg.setLevel(saved_levels.get(lg.name, logging.WARNING))

    asyncio.create_task(_run())
    return {"status": "started", "message": "Log sync started for all collectors."}


@router.get("/sync/status")
async def get_sync_status():
    """Return current sync status and captured log entries."""
    return _sync_status

# ── helpers ────────────────────────────────────────────────────────────────

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500


def _clamp(limit: int) -> int:
    return max(1, min(limit, _MAX_LIMIT))


# ── Sign-in logs ──────────────────────────────────────────────────────────

@router.get("/signin")
def list_signin_logs(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    user: Optional[str] = None,
    risk_level: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
):
    q = db.query(SignInLog)
    if user:
        q = q.filter(SignInLog.user_principal_name.ilike(f"%{user}%"))
    if risk_level:
        q = q.filter(SignInLog.risk_level_during_sign_in == risk_level)
    if since:
        q = q.filter(SignInLog.created_date_time >= since)
    if until:
        q = q.filter(SignInLog.created_date_time <= until)

    total = q.count()
    items = (
        q.order_by(desc(SignInLog.created_date_time))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": [_signin_to_dict(r) for r in items]}


def _signin_to_dict(r: SignInLog) -> dict:
    return {
        "id": r.id,
        "user_display_name": r.user_display_name,
        "user_principal_name": r.user_principal_name,
        "user_id": r.user_id,
        "app_display_name": r.app_display_name,
        "ip_address": r.ip_address,
        "location_city": r.location_city,
        "location_country": r.location_country,
        "status_error_code": r.status_error_code,
        "status_failure_reason": r.status_failure_reason,
        "risk_level_during_signin": r.risk_level_during_sign_in,
        "risk_level_aggregated": r.risk_level_aggregated,
        "risk_state": r.risk_state,
        "mfa_detail": r.mfa_detail,
        "is_interactive": r.is_interactive,
        "conditional_access_status": r.conditional_access_status,
        "created_datetime": r.created_date_time.isoformat() if r.created_date_time is not None else None,
    }


# ── Audit logs ────────────────────────────────────────────────────────────

@router.get("/audit")
def list_audit_logs(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    category: Optional[str] = None,
    activity: Optional[str] = None,
    initiated_by: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
):
    q = db.query(AuditLog)
    if category:
        q = q.filter(AuditLog.category == category)
    if activity:
        q = q.filter(AuditLog.activity_display_name.ilike(f"%{activity}%"))
    if initiated_by:
        q = q.filter(AuditLog.initiated_by_user_upn.ilike(f"%{initiated_by}%"))
    if since:
        q = q.filter(AuditLog.activity_date_time >= since)
    if until:
        q = q.filter(AuditLog.activity_date_time <= until)

    total = q.count()
    items = (
        q.order_by(desc(AuditLog.activity_date_time))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": [_audit_to_dict(r) for r in items]}


def _audit_to_dict(r: AuditLog) -> dict:
    return {
        "id": r.id,
        "category": r.category,
        "activity_display_name": r.activity_display_name,
        "activity_datetime": r.activity_date_time.isoformat() if r.activity_date_time is not None else None,
        "result": r.result,
        "result_reason": r.result_reason,
        "initiated_by_user": r.initiated_by_user_upn,
        "initiated_by_app": r.initiated_by_app_display_name,
        "target_resources": r.target_resources,
        "correlation_id": r.correlation_id,
    }


# ── O365 / SharePoint / PowerApps activity ───────────────────────────────

@router.get("/activity")
def list_activity_logs(
    db: Session = Depends(get_db),
    offset: int = Query(0, ge=0),
    limit: int = Query(_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    source: Optional[str] = None,
    user: Optional[str] = None,
    operation: Optional[str] = None,
    workload: Optional[str] = None,
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
):
    q = db.query(O365ActivityLog)
    if source:
        try:
            q = q.filter(O365ActivityLog.source == LogSource(source))
        except ValueError:
            pass
    if user:
        q = q.filter(O365ActivityLog.user_id.ilike(f"%{user}%"))
    if operation:
        q = q.filter(O365ActivityLog.operation.ilike(f"%{operation}%"))
    if workload:
        q = q.filter(O365ActivityLog.workload == workload)
    if since:
        q = q.filter(O365ActivityLog.creation_time >= since)
    if until:
        q = q.filter(O365ActivityLog.creation_time <= until)

    total = q.count()
    items = (
        q.order_by(desc(O365ActivityLog.creation_time))
        .offset(offset)
        .limit(_clamp(limit))
        .all()
    )
    return {"total": total, "offset": offset, "limit": _clamp(limit), "items": [_activity_to_dict(r) for r in items]}


def _activity_to_dict(r: O365ActivityLog) -> dict:
    return {
        "id": r.id,
        "source": r.source.value if r.source is not None else None,
        "workload": r.workload,
        "operation": r.operation,
        "user_id": r.user_id,
        "client_ip": r.client_ip,
        "creation_time": r.creation_time.isoformat() if r.creation_time is not None else None,
        "result_status": r.result_status,
        "object_id": r.object_id,
        "site_url": r.site_url,
        "source_file_name": r.source_file_name,
        "app_name": r.app_name,
        "environment_name": r.environment_name,
    }
