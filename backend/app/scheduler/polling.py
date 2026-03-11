"""APScheduler-based polling daemon.

Runs collectors → rules engine → anomaly detection → alerting on a
configurable interval (default 15 minutes).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session

from app.alerting.dispatcher import AlertDispatcher
from app.analyzers.anomaly import AnomalyDetector
from app.analyzers.rules_engine import CorrelationRulesEngine
from app.auth.msal_client import get_auth_client
from app.collectors.entra_audit import EntraAuditCollector
from app.collectors.entra_signin import EntraSignInCollector
from app.collectors.office365 import Office365Collector
from app.collectors.powerapps import PowerAppsCollector
from app.collectors.sharepoint import SharePointCollector
from app.config import get_settings
from app.models.database import (
    CollectorState,
    LogSource,
    get_session_factory,
    init_db,
)

logger = logging.getLogger(__name__)


async def run_collection_cycle() -> None:
    """Execute one full collect → analyse → alert cycle."""
    settings = get_settings()
    session_factory = get_session_factory()
    db: Session = session_factory()

    try:
        auth = get_auth_client()

        # Acquire tokens – gracefully handle missing credentials
        graph_token: str | None = None
        o365_token: str | None = None

        if auth.is_configured:
            try:
                graph_token = auth.get_graph_token()
            except Exception:
                logger.exception("Failed to acquire Graph token")
            try:
                o365_token = auth.get_o365_mgmt_token()
            except Exception:
                logger.exception("Failed to acquire O365 token")
        else:
            logger.warning(
                "App-registration credentials not configured – "
                "only interactive-mode collection is possible "
                "(O365/SharePoint/PowerApps collectors will be skipped)"
            )

        logger.info("=== Starting collection cycle ===")
        all_incidents = []

        # ── Collect ───────────────────────────────────────────────────
        collectors: list[tuple] = []

        # Graph-backed collectors (Entra sign-in + audit) need a Graph token
        if graph_token:
            collectors.append(
                (EntraSignInCollector(http_client=None), graph_token, LogSource.ENTRA_SIGNIN)
            )
            collectors.append(
                (EntraAuditCollector(http_client=None), graph_token, LogSource.ENTRA_AUDIT)
            )
        else:
            logger.warning("Skipping Entra collectors – no Graph token available")

        # O365-backed collectors require application-permission tokens
        if o365_token:
            o365_collectors = [
                Office365Collector(
                    tenant_id=settings.azure_tenant_id,
                    content_type="Audit.Exchange",
                    source=LogSource.OFFICE365,
                ),
                SharePointCollector(tenant_id=settings.azure_tenant_id),
                PowerAppsCollector(tenant_id=settings.azure_tenant_id),
            ]
            o365_sources = [LogSource.OFFICE365, LogSource.SHAREPOINT, LogSource.POWERAPPS]

            # Ensure O365 Management subscriptions are active before polling
            for coll in o365_collectors:
                try:
                    await coll.ensure_subscription(o365_token)
                except Exception:
                    logger.warning(
                        "Subscription setup for '%s' failed — will attempt "
                        "collection anyway (may 401 if admin consent is missing; "
                        "grant ActivityFeed.Read in Entra ID → API permissions → "
                        "Grant admin consent)",
                        coll.collector_name,
                    )

            collectors.extend(
                [(c, o365_token, s) for c, s in zip(o365_collectors, o365_sources)]
            )
        else:
            logger.warning(
                "Skipping O365/SharePoint/PowerApps collectors – "
                "no O365 Management token available"
            )

        for collector, token, source in collectors:
            try:
                since = _get_last_collected(db, collector.collector_name)
                until = datetime.now(timezone.utc)
                raw = await collector.collect(token=token, since=since, until=until)
                records = collector.normalize(raw)

                for rec in records:
                    db.merge(rec)
                db.flush()

                # Evaluate rules on new records
                engine = CorrelationRulesEngine(db)
                incidents = engine.evaluate_new_logs(records, source)
                all_incidents.extend(incidents)

                _update_last_collected(db, collector.collector_name)

                # Commit after each collector so records are immediately visible
                db.commit()

                logger.info(
                    "Collector '%s': %d records, %d incidents",
                    collector.collector_name,
                    len(records),
                    len(incidents),
                )
            except Exception:
                logger.exception("Collector '%s' failed", collector.collector_name)
                db.rollback()

        # ── Meta-rules ────────────────────────────────────────────────
        try:
            engine = CorrelationRulesEngine(db)
            meta_incidents = engine.evaluate_meta_rules()
            all_incidents.extend(meta_incidents)
            db.commit()
            logger.info("Meta-rules produced %d incidents", len(meta_incidents))
        except Exception:
            logger.exception("Meta-rule evaluation failed")
            db.rollback()

        # ── Anomaly detection ─────────────────────────────────────────
        try:
            detector = AnomalyDetector(db)
            anomaly_incidents = detector.detect_all()
            all_incidents.extend(anomaly_incidents)
            db.commit()
            logger.info("Anomaly detection produced %d incidents", len(anomaly_incidents))
        except Exception:
            logger.exception("Anomaly detection failed")
            db.rollback()

        # ── User sign-in profiles ─────────────────────────────────────
        try:
            from app.analyzers.user_profiles import refresh_all_profiles
            profile_result = refresh_all_profiles(db)
            db.commit()
            logger.info(
                "User profiles: %d updated, %d risky",
                profile_result["updated"],
                profile_result["newly_risky"],
            )
        except Exception:
            logger.exception("User profile refresh failed")
            db.rollback()

        # ── Expire watch windows ──────────────────────────────────────
        try:
            engine = CorrelationRulesEngine(db)
            expired = engine.expire_watch_windows()
            db.commit()
            logger.info("Expired %d watch windows", expired)
        except Exception:
            logger.exception("Watch window expiration failed")
            db.rollback()

        # ── Alert ─────────────────────────────────────────────────────
        if all_incidents:
            try:
                dispatcher = AlertDispatcher(db)
                sent = await dispatcher.dispatch(all_incidents)
                db.commit()
                logger.info("Dispatched %d alert deliveries for %d incidents", sent, len(all_incidents))
            except Exception:
                logger.exception("Alert dispatch failed")
                db.rollback()

        logger.info("=== Collection cycle complete: %d total incidents ===", len(all_incidents))

    except Exception:
        logger.exception("Collection cycle failed critically")
        db.rollback()
    finally:
        db.close()


def _get_last_collected(db: Session, collector_name: str) -> datetime:
    """Retrieve last successful collection time, or default to 24h ago."""
    state = db.query(CollectorState).filter_by(collector_name=collector_name).first()
    if state and state.last_successful_poll:
        return state.last_successful_poll
    return datetime.now(timezone.utc) - timedelta(hours=24)


def _update_last_collected(db: Session, collector_name: str) -> None:
    now = datetime.now(timezone.utc)
    state = db.query(CollectorState).filter_by(collector_name=collector_name).first()
    if state:
        state.last_successful_poll = now
    else:
        db.add(CollectorState(collector_name=collector_name, last_successful_poll=now))
    db.flush()


def create_scheduler() -> AsyncIOScheduler:
    """Create and configure the APScheduler instance."""
    settings = get_settings()
    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        run_collection_cycle,
        "interval",
        minutes=settings.poll_interval_minutes,
        id="collection_cycle",
        name="Log collection + analysis cycle",
        replace_existing=True,
        max_instances=1,
    )
    return scheduler


async def start_daemon() -> None:
    """Initialise DB, seed rules, and start the scheduler."""
    init_db()

    # Seed built-in rules
    session_factory = get_session_factory()
    db = session_factory()
    try:
        from app.analyzers.seed_rules import seed_rules
        count = seed_rules(db)
        db.commit()
        if count:
            logger.info("Seeded %d built-in correlation rules", count)
    finally:
        db.close()

    scheduler = create_scheduler()
    scheduler.start()

    # Run immediately, then let the scheduler take over
    await run_collection_cycle()

    logger.info("Daemon started – polling every %d minutes", get_settings().poll_interval_minutes)

    # Keep running until interrupted
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown(wait=False)
        logger.info("Daemon stopped")
