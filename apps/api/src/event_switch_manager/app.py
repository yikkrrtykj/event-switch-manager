from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import router
from .database import create_database_engine, upgrade_database
from .plan_api import router as plan_router
from .security import LocalWebGuard
from .settings import Settings


def create_app(settings: Settings) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_database_engine(settings.database_path)
        try:
            upgrade_database(engine)
            app.state.engine = engine
            yield
        finally:
            engine.dispose()

    app = FastAPI(
        title="Event Switch Manager API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.add_middleware(
        LocalWebGuard, authorities=settings.allowed_authorities, development=settings.development
    )
    app.include_router(router)
    app.include_router(plan_router)

    web_dist = settings.web_dist.resolve()
    assets = web_dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        index = web_dist / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=404, detail="Build the frontend before serving it")
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    return app
