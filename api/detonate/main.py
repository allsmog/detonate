import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from detonate.api.deps import get_storage
from detonate.api.routes import (
    ai,
    analyses,
    auth,
    chat,
    comments,
    dashboard,
    health,
    ioc_export,
    machines,
    mitre,
    network_analysis,
    reports,
    search,
    static_analysis,
    submissions,
    teams,
    threat_intel,
    url_submit,
    vnc,
    webhooks,
    yara_management,
)
from detonate.api.routes import (
    settings as settings_routes,
)
from detonate.config import settings
from detonate.services.llm import is_provider_configured

logger = logging.getLogger("detonate")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Startup: ensure MinIO bucket exists
    storage = get_storage()
    storage.ensure_bucket()

    if settings.ai_enabled and not is_provider_configured():
        logger.warning(
            "AI is enabled but LLM provider '%s' is not configured "
            "(missing API key?). AI endpoints will return 503.",
            settings.llm_provider,
        )

    # Startup: initialize machine pool if enabled
    if settings.sandbox_pool_enabled:
        from detonate.services.machine_pool import get_machine_pool

        pool = get_machine_pool()
        try:
            await pool.initialize(settings.sandbox_pool_size)
            logger.info("Machine pool initialized with %d containers", settings.sandbox_pool_size)
        except Exception:
            logger.exception("Failed to initialize machine pool")

    yield

    # Shutdown: destroy all active VNC sessions
    from detonate.services.vnc import VNCManager

    vnc_manager = VNCManager.get_instance()
    destroyed = await vnc_manager.destroy_all()
    if destroyed:
        logger.info("Destroyed %d VNC session(s) during shutdown", destroyed)

    # Shutdown: tear down machine pool
    if settings.sandbox_pool_enabled:
        from detonate.services.machine_pool import get_machine_pool

        pool = get_machine_pool()
        try:
            await pool.shutdown()
            logger.info("Machine pool shut down")
        except Exception:
            logger.exception("Failed to shut down machine pool")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Detonate",
        description="Open-source malware analysis sandbox",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom validation error handler
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        errors = []
        for error in exc.errors():
            loc = " -> ".join(str(part) for part in error["loc"])
            errors.append(f"{loc}: {error['msg']}")
        return JSONResponse(
            status_code=422,
            content={"detail": "; ".join(errors)},
        )

    # Routes
    app.include_router(health.router, prefix="/api/v1")
    app.include_router(auth.router, prefix="/api/v1")
    app.include_router(submissions.router, prefix="/api/v1")
    app.include_router(ai.router, prefix="/api/v1")
    app.include_router(chat.router, prefix="/api/v1")
    app.include_router(analyses.router, prefix="/api/v1")
    app.include_router(machines.router, prefix="/api/v1")
    app.include_router(vnc.router, prefix="/api/v1")
    app.include_router(threat_intel.router, prefix="/api/v1")
    app.include_router(mitre.router, prefix="/api/v1")
    app.include_router(search.router, prefix="/api/v1")
    app.include_router(dashboard.router, prefix="/api/v1")
    app.include_router(static_analysis.router, prefix="/api/v1")
    app.include_router(ioc_export.router, prefix="/api/v1")
    app.include_router(url_submit.router, prefix="/api/v1")
    app.include_router(webhooks.router, prefix="/api/v1")
    app.include_router(reports.router, prefix="/api/v1")
    app.include_router(teams.router, prefix="/api/v1")
    app.include_router(comments.router, prefix="/api/v1")
    app.include_router(network_analysis.router, prefix="/api/v1")
    app.include_router(yara_management.router, prefix="/api/v1")
    app.include_router(settings_routes.router, prefix="/api/v1")

    return app


app = create_app()
