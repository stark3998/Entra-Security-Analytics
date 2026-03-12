"""FastAPI application factory with lifespan, CORS, and router wiring."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_auth import router as auth_router
from app.api.routes_auth import settings_router
from app.api.routes_capolicies import router as capolicies_router
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_incidents import router as incidents_router
from app.api.routes_logs import router as logs_router
from app.api.routes_rules import router as rules_router
from app.api.routes_pim import router as pim_router
from app.api.routes_user_profiles import router as user_profiles_router
from app.auth.token_validator import get_current_user
from app.config import get_settings
from app.models.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    settings = get_settings()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )
    logger = logging.getLogger(__name__)

    # Initialise database & seed rules
    init_db()
    from app.analyzers.seed_rules import seed_rules
    from app.models.database import get_session_factory

    db = get_session_factory()()
    try:
        count = seed_rules(db)
        db.commit()
        if count:
            logger.info("Seeded %d built-in correlation rules", count)
    finally:
        db.close()

    logger.info("Log Analytics API ready")
    yield
    logger.info("Shutting down")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Log Analytics – SIEM-lite",
        description="Microsoft cloud log collection, correlation, and alerting",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers – auth & settings (public / self-protecting)
    app.include_router(auth_router)
    app.include_router(settings_router)

    # Routers – protected by JWT when interactive auth is active
    auth_dep = [Depends(get_current_user)]
    app.include_router(logs_router, dependencies=auth_dep)
    app.include_router(incidents_router, dependencies=auth_dep)
    app.include_router(rules_router, dependencies=auth_dep)
    app.include_router(dashboard_router, dependencies=auth_dep)
    app.include_router(capolicies_router, dependencies=auth_dep)
    app.include_router(pim_router, dependencies=auth_dep)
    app.include_router(user_profiles_router, dependencies=auth_dep)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


app = create_app()
