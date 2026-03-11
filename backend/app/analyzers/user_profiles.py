"""User sign-in profile builder and new-location risk detector.

Aggregates sign-in logs per user into a historical profile and flags users
as risky when a previously-unseen location is encountered.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.database import SignInLog, UserSignInProfile

logger = logging.getLogger(__name__)


def refresh_all_profiles(db: Session) -> dict[str, Any]:
    """Rebuild every user profile from sign-in logs and detect new locations.

    Returns a summary dict with counts of profiles updated and users flagged.
    """
    # Group sign-in logs by user
    users = (
        db.query(SignInLog.user_principal_name)
        .distinct()
        .all()
    )
    upn_list = [u[0] for u in users if u[0]]

    updated = 0
    newly_risky = 0

    for upn in upn_list:
        profile = _build_profile(db, upn)
        if profile:
            db.merge(profile)
            updated += 1
            if profile.is_risky:
                newly_risky += 1

    db.flush()
    logger.info(
        "User profiles refreshed: %d updated, %d flagged risky",
        updated,
        newly_risky,
    )
    return {"updated": updated, "newly_risky": newly_risky}


def refresh_profile_for_user(db: Session, upn: str) -> UserSignInProfile | None:
    """Rebuild the profile for a single user and return it."""
    profile = _build_profile(db, upn)
    if profile:
        db.merge(profile)
        db.flush()
    return profile


def _build_profile(db: Session, upn: str) -> UserSignInProfile | None:
    """Aggregate all sign-in logs for *upn* into a UserSignInProfile."""
    logs = (
        db.query(SignInLog)
        .filter(SignInLog.user_principal_name == upn)
        .order_by(SignInLog.created_date_time.asc())
        .all()
    )
    if not logs:
        return None

    # Fetch existing profile so we can compare for new locations
    existing = db.query(UserSignInProfile).filter_by(user_principal_name=upn).first()
    old_location_keys: set[str] = set()
    if existing and existing.known_locations:
        for loc in existing.known_locations:
            key = _location_key(loc.get("city", ""), loc.get("country", ""))
            old_location_keys.add(key)

    # ── Aggregate ──────────────────────────────────────────────
    location_map: dict[str, dict] = {}
    device_map: dict[str, dict] = {}
    ip_map: dict[str, dict] = {}
    hour_hist = [0] * 24

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    display_name = ""
    user_id = ""

    for log in logs:
        ts = log.created_date_time
        if ts is None:
            continue

        if first_seen is None or ts < first_seen:
            first_seen = ts
        if last_seen is None or ts > last_seen:
            last_seen = ts

        display_name = log.user_display_name or display_name
        user_id = log.user_id or user_id

        # Hour histogram
        hour_hist[ts.hour] += 1

        # Locations
        loc_key = _location_key(log.location_city or "", log.location_country or "")
        if loc_key:
            if loc_key not in location_map:
                location_map[loc_key] = {
                    "city": log.location_city or "",
                    "state": log.location_state or "",
                    "country": log.location_country or "",
                    "lat": log.latitude,
                    "lon": log.longitude,
                    "first_seen": ts.isoformat(),
                    "last_seen": ts.isoformat(),
                    "count": 0,
                }
            entry = location_map[loc_key]
            entry["last_seen"] = ts.isoformat()
            entry["count"] += 1
            # Update lat/lon if available
            if log.latitude is not None:
                entry["lat"] = log.latitude
            if log.longitude is not None:
                entry["lon"] = log.longitude

        # Devices
        dev_key = f"{log.device_os or ''}|{log.device_browser or ''}"
        if dev_key != "|":
            if dev_key not in device_map:
                device_map[dev_key] = {
                    "device_os": log.device_os or "",
                    "device_browser": log.device_browser or "",
                    "device_id": log.device_id or "",
                    "first_seen": ts.isoformat(),
                    "last_seen": ts.isoformat(),
                    "count": 0,
                }
            d_entry = device_map[dev_key]
            d_entry["last_seen"] = ts.isoformat()
            d_entry["count"] += 1

        # IPs
        ip = log.ip_address or ""
        if ip:
            if ip not in ip_map:
                ip_map[ip] = {
                    "ip_address": ip,
                    "first_seen": ts.isoformat(),
                    "last_seen": ts.isoformat(),
                    "count": 0,
                }
            ip_map[ip]["last_seen"] = ts.isoformat()
            ip_map[ip]["count"] += 1

    # ── Detect new locations ───────────────────────────────────
    new_location_keys = set(location_map.keys()) - old_location_keys
    risk_reasons: list[str] = []
    is_risky = False

    # Only flag if the user had prior history (not first-time build)
    if old_location_keys and new_location_keys:
        is_risky = True
        for key in new_location_keys:
            loc = location_map[key]
            label = ", ".join(filter(None, [loc["city"], loc["country"]]))
            risk_reasons.append(f"new_location: {label}")

    # Sort aggregations by count descending
    sorted_locations = sorted(location_map.values(), key=lambda x: x["count"], reverse=True)
    sorted_devices = sorted(device_map.values(), key=lambda x: x["count"], reverse=True)
    sorted_ips = sorted(ip_map.values(), key=lambda x: x["count"], reverse=True)

    profile = UserSignInProfile(
        user_principal_name=upn,
        user_display_name=display_name,
        user_id=user_id,
        known_locations=sorted_locations,
        known_devices=sorted_devices,
        known_ips=sorted_ips,
        sign_in_hour_histogram=hour_hist,
        total_sign_ins=len(logs),
        first_seen=first_seen,
        last_seen=last_seen,
        is_risky=is_risky,
        risk_reasons=risk_reasons,
        risk_flagged_at=datetime.now(timezone.utc) if is_risky else (
            existing.risk_flagged_at if existing else None
        ),
    )
    return profile


def _location_key(city: str, country: str) -> str:
    """Create a stable key for a city+country combination."""
    c = (city or "").strip().lower()
    co = (country or "").strip().lower()
    if not c and not co:
        return ""
    return f"{c}|{co}"
