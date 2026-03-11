"""CLI entry-point — on-demand commands for collection, analysis, and serving."""

from __future__ import annotations

import asyncio
import logging
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        stream=sys.stderr,
    )


# ── Main group ────────────────────────────────────────────────────────────

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def cli(verbose: bool) -> None:
    """Log Analytics – SIEM-lite CLI"""
    _setup_logging(verbose)


# ── collect ───────────────────────────────────────────────────────────────

@cli.command()
@click.option("--source", type=click.Choice(
    ["entra-signin", "entra-audit", "office365", "sharepoint", "powerapps", "all"],
    case_sensitive=False,
), default="all", help="Log source to collect")
def collect(source: str) -> None:
    """Run a one-shot log collection cycle."""
    from app.scheduler.polling import run_collection_cycle

    console.print(f"[bold]Collecting logs: {source}[/bold]")
    asyncio.run(run_collection_cycle())
    console.print("[green]Collection complete[/green]")


# ── analyze ───────────────────────────────────────────────────────────────

@cli.command()
def analyze() -> None:
    """Run rules engine, anomaly detection, and meta-rules."""
    from app.analyzers.anomaly import AnomalyDetector
    from app.analyzers.rules_engine import CorrelationRulesEngine
    from app.analyzers.seed_rules import seed_rules
    from app.models.database import get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        seed_rules(db)
        db.commit()

        engine = CorrelationRulesEngine(db)
        meta = engine.evaluate_meta_rules()
        expired = engine.expire_watch_windows()

        detector = AnomalyDetector(db)
        anomalies = detector.detect_all()
        db.commit()

        console.print(f"Meta-rule incidents: [cyan]{len(meta)}[/cyan]")
        console.print(f"Anomaly incidents:   [cyan]{len(anomalies)}[/cyan]")
        console.print(f"Expired watches:     [cyan]{expired}[/cyan]")
    finally:
        db.close()


# ── serve ─────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1")
@click.option("--port", default=8000, type=int)
@click.option("--reload", "do_reload", is_flag=True, help="Enable auto-reload")
def serve(host: str, port: int, do_reload: bool) -> None:
    """Start the FastAPI web server."""
    import uvicorn

    console.print(f"[bold]Starting server on {host}:{port}[/bold]")
    uvicorn.run("app.main:app", host=host, port=port, reload=do_reload)


# ── daemon ────────────────────────────────────────────────────────────────

@cli.command()
def daemon() -> None:
    """Start the polling daemon (scheduler + web server)."""
    from app.scheduler.polling import start_daemon

    console.print("[bold]Starting daemon mode[/bold]")
    asyncio.run(start_daemon())


# ── rules ─────────────────────────────────────────────────────────────────

@cli.group()
def rules() -> None:
    """Manage correlation rules."""


@rules.command("list")
@click.option("--enabled-only", is_flag=True)
def rules_list(enabled_only: bool) -> None:
    """List all correlation rules."""
    from app.models.database import CorrelationRule, get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        q = db.query(CorrelationRule)
        if enabled_only:
            q = q.filter(CorrelationRule.enabled.is_(True))
        rules_rows = q.order_by(CorrelationRule.slug).all()

        table = Table(title="Correlation Rules")
        table.add_column("ID", style="dim")
        table.add_column("Slug")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Enabled")
        table.add_column("System")

        for r in rules_rows:
            table.add_row(
                str(r.id),
                r.slug,
                r.name,
                r.severity.value if r.severity else "",
                "✓" if r.enabled else "✗",
                "✓" if r.is_system else "✗",
            )
        console.print(table)
    finally:
        db.close()


@rules.command("toggle")
@click.argument("slug")
def rules_toggle(slug: str) -> None:
    """Toggle a rule on/off by slug."""
    from app.models.database import CorrelationRule, get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        rule = db.query(CorrelationRule).filter_by(slug=slug).first()
        if not rule:
            console.print(f"[red]Rule '{slug}' not found[/red]")
            return
        rule.enabled = not rule.enabled
        db.commit()
        state = "enabled" if rule.enabled else "disabled"
        console.print(f"Rule [cyan]{slug}[/cyan] is now [bold]{state}[/bold]")
    finally:
        db.close()


# ── incidents ─────────────────────────────────────────────────────────────

@cli.group()
def incidents() -> None:
    """View and manage incidents."""


@incidents.command("list")
@click.option("--status", type=click.Choice(["open", "investigating", "resolved", "closed", "false_positive"], case_sensitive=False))
@click.option("--limit", default=20, type=int)
def incidents_list(status: str | None, limit: int) -> None:
    """List recent incidents."""
    from app.models.database import Incident, IncidentStatus, get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        q = db.query(Incident)
        if status:
            q = q.filter(Incident.status == IncidentStatus(status))
        rows = q.order_by(Incident.created_at.desc()).limit(limit).all()

        table = Table(title="Incidents")
        table.add_column("ID", style="dim")
        table.add_column("Rule")
        table.add_column("Severity")
        table.add_column("User")
        table.add_column("Status")
        table.add_column("Created")

        for i in rows:
            table.add_row(
                str(i.id),
                (i.rule.slug if i.rule else "") or "",
                i.severity.value if i.severity else "",
                i.user_id or "",
                i.status.value if i.status else "",
                i.created_at.strftime("%Y-%m-%d %H:%M") if i.created_at else "",
            )
        console.print(table)
    finally:
        db.close()


@incidents.command("resolve")
@click.argument("incident_id", type=int)
@click.option("--notes", default="", help="Resolution notes")
def incidents_resolve(incident_id: int, notes: str) -> None:
    """Mark an incident as resolved."""
    from app.models.database import Incident, IncidentStatus, get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        inc = db.query(Incident).get(incident_id)
        if not inc:
            console.print(f"[red]Incident #{incident_id} not found[/red]")
            return
        inc.status = IncidentStatus.RESOLVED
        if notes:
            inc.notes = notes
        db.commit()
        console.print(f"[green]Incident #{incident_id} resolved[/green]")
    finally:
        db.close()


# ── risk ──────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--threshold", default=50, type=int, help="Minimum risk score to display")
def risk(threshold: int) -> None:
    """Show high-risk users."""
    from app.analyzers.risk_scorer import RiskScorer
    from app.models.database import get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        scorer = RiskScorer(db)
        results = scorer.get_high_risk_users(threshold=threshold)

        table = Table(title=f"High-Risk Users (≥{threshold})")
        table.add_column("User ID")
        table.add_column("Score", justify="right")
        table.add_column("Active Windows", justify="right")
        table.add_column("Entra Risk")
        table.add_column("Multiplier", justify="right")

        for r in results:
            table.add_row(
                r.user_id,
                str(r.score),
                str(r.active_windows),
                r.entra_risk_level or "none",
                f"{r.multiplier:.2f}",
            )
        console.print(table)
    finally:
        db.close()


# ── ca-policies ───────────────────────────────────────────────────────────

@cli.group("ca-policies")
def ca_policies() -> None:
    """Manage Conditional Access policy data."""


@ca_policies.command("sync")
def ca_sync() -> None:
    """Sync CA policies, named locations, auth strengths & groups from Graph."""
    from app.auth.msal_client import get_auth_client
    from app.collectors.ca_policies import CAPolicyCollector
    from app.models.database import get_session_factory, init_db

    init_db()
    auth = get_auth_client()
    if not auth.is_configured:
        console.print("[red]MSAL client not configured — set app registration first[/red]")
        return

    token = auth.get_graph_token()
    db = get_session_factory()()
    try:
        collector = CAPolicyCollector()
        counts = asyncio.run(collector.sync_all(token, db))
        console.print("[green]Sync complete:[/green]")
        for k, v in counts.items():
            console.print(f"  {k}: [cyan]{v}[/cyan]")
    finally:
        db.close()


@ca_policies.command("list")
@click.option("--state", type=click.Choice(["enabled", "disabled", "enabledForReportingButNotEnforced"], case_sensitive=False))
def ca_list(state: str | None) -> None:
    """List cached conditional access policies."""
    from app.models.database import ConditionalAccessPolicy, get_session_factory, init_db

    init_db()
    db = get_session_factory()()
    try:
        q = db.query(ConditionalAccessPolicy)
        if state:
            q = q.filter(ConditionalAccessPolicy.state == state)
        rows = q.order_by(ConditionalAccessPolicy.display_name).all()

        table = Table(title="Conditional Access Policies")
        table.add_column("ID", style="dim", max_width=10)
        table.add_column("Name")
        table.add_column("State")
        table.add_column("Modified")

        for p in rows:
            table.add_row(
                p.id[:10],
                p.display_name,
                p.state,
                p.modified_date_time.strftime("%Y-%m-%d") if p.modified_date_time else "",
            )
        console.print(table)
    finally:
        db.close()


@ca_policies.command("show")
@click.argument("policy_id")
def ca_show(policy_id: str) -> None:
    """Show detail for a single policy."""
    from app.models.database import (
        ConditionalAccessPolicy,
        PolicyCoverageCache,
        get_session_factory,
        init_db,
    )

    init_db()
    db = get_session_factory()()
    try:
        policy = db.query(ConditionalAccessPolicy).get(policy_id)
        if not policy:
            console.print(f"[red]Policy '{policy_id}' not found[/red]")
            return

        console.print(f"\n[bold]{policy.display_name}[/bold]  ({policy.state})")
        console.print(f"  ID:       {policy.id}")
        console.print(f"  Created:  {policy.created_date_time}")
        console.print(f"  Modified: {policy.modified_date_time}")

        conditions = policy.conditions or {}
        console.print("\n  [bold]Conditions:[/bold]")
        for key, val in conditions.items():
            console.print(f"    {key}: {val}")

        grant = policy.grant_controls or {}
        console.print("\n  [bold]Grant Controls:[/bold]")
        for key, val in grant.items():
            console.print(f"    {key}: {val}")

        coverage = db.query(PolicyCoverageCache).filter_by(policy_id=policy_id).all()
        if coverage:
            console.print(f"\n  [bold]Coverage Entries ({len(coverage)}):[/bold]")
            table = Table()
            table.add_column("Type")
            table.add_column("Entity")
            table.add_column("Include/Exclude")
            for c in coverage:
                table.add_row(c.entity_type, c.entity_display_name or c.entity_id, c.inclusion_type)
            console.print(table)
    finally:
        db.close()


@ca_policies.command("coverage")
def ca_coverage() -> None:
    """Show coverage summary across all policies."""
    from app.models.database import (
        ConditionalAccessPolicy,
        PolicyCoverageCache,
        get_session_factory,
        init_db,
    )
    from sqlalchemy import func as sqlfunc

    init_db()
    db = get_session_factory()()
    try:
        total = db.query(sqlfunc.count(ConditionalAccessPolicy.id)).scalar() or 0
        console.print(f"\n[bold]Total Policies:[/bold] {total}")

        results = (
            db.query(
                PolicyCoverageCache.entity_type,
                PolicyCoverageCache.inclusion_type,
                sqlfunc.count(sqlfunc.distinct(PolicyCoverageCache.entity_id)),
            )
            .group_by(PolicyCoverageCache.entity_type, PolicyCoverageCache.inclusion_type)
            .all()
        )

        table = Table(title="Coverage Summary")
        table.add_column("Entity Type")
        table.add_column("Inclusion")
        table.add_column("Unique Entities", justify="right")

        for etype, incl, cnt in results:
            table.add_row(etype, incl, str(cnt))
        console.print(table)
    finally:
        db.close()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
