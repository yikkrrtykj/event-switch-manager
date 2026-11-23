from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from typing import Any, cast

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import router
from .config_assembly_api import router as assembly_router
from .database import create_database_engine, upgrade_database
from .l2_validation_api import router as validation_router
from .layer3_api import router as layer3_router
from .layer3_cli_api import router as layer3_cli_router
from .management_api import router as management_router
from .plan_api import router as plan_router
from .security import LocalWebGuard
from .settings import Settings

_L2_COMPONENT_PREFIX = "event_switch_manager__planning__layer2_"
_L3_COMPONENT_PREFIX = "event_switch_manager__planning__layer3_"
_COMPONENT_PREFIX = "#/components/schemas/"


def _isolate_openapi_component_names(
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Rewrite only generated OpenAPI component keys, never Python classes.

    FastAPI derives component names from Python class names.  L2 and L3 have
    deliberately separate frozen model graphs but a few classes share names
    (for example ``ValidationSafety``).  When both response-model graphs are
    exposed in one app, FastAPI qualifies both sides.  This deterministic
    schema-level pass restores L2's established plain component names and
    namespaces only the conflicting L3 nested components.  Python classes,
    model fields and wire payloads are not touched.
    """
    transformed = deepcopy(schema)
    components_raw = transformed.get("components", {}).get("schemas")
    if not isinstance(components_raw, dict):
        return transformed
    components = cast(dict[str, Any], components_raw)

    def refs_of(value: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str):
                    if item.startswith(_COMPONENT_PREFIX):
                        found.add(item.removeprefix(_COMPONENT_PREFIX))
                else:
                    found.update(refs_of(item))
        elif isinstance(value, list):
            for item in value:
                found.update(refs_of(item))
        return found

    def reachable(roots: tuple[str, ...]) -> set[str]:
        seen: set[str] = set()
        stack = [name for name in roots if name in components]
        while stack:
            name = stack.pop()
            if name in seen:
                continue
            seen.add(name)
            stack.extend(refs_of(components[name]))
        return seen

    l2_roots = ("ValidationReport", "L2CliCandidateDocument")
    l3_roots = ("L3CandidateDocument", "L3ValidationReport")
    l2_reachable = reachable(l2_roots)
    l3_reachable = reachable(l3_roots)

    mapping: dict[str, str] = {}
    l2_names: dict[str, list[str]] = {}
    for name in components:
        if name.startswith(_L2_COMPONENT_PREFIX):
            suffix = name.rsplit("__", 1)[-1]
            l2_names.setdefault(suffix, []).append(name)
    for suffix, names in l2_names.items():
        if len(names) == 1:
            mapping[names[0]] = suffix
    for name in components:
        if name.startswith(_L3_COMPONENT_PREFIX):
            mapping[name] = f"L3Cli{name.rsplit('__', 1)[-1]}"
    for name in l3_reachable - l2_reachable:
        if name in l3_roots or name in mapping:
            continue
        if name.startswith("L3Cli"):
            continue
        if not name.startswith(_L3_COMPONENT_PREFIX):
            mapping[name] = f"L3Cli{name}"
    if not mapping:
        return transformed

    existing = set(components) - set(mapping)
    targets: set[str] = set()
    for new_name in mapping.values():
        if new_name in existing or new_name in targets:
            raise RuntimeError("OpenAPI component name collision")
        targets.add(new_name)

    renamed: dict[str, Any] = {}
    for name in components:
        renamed[mapping.get(name, name)] = components[name]
    if len(renamed) != len(components):
        raise RuntimeError("OpenAPI component overwrite")
    transformed["components"]["schemas"] = renamed

    def rewrite_refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str):
                    if item.startswith(_COMPONENT_PREFIX):
                        target = item.removeprefix(_COMPONENT_PREFIX)
                        if target in mapping:
                            value[key] = (
                                f"{_COMPONENT_PREFIX}{mapping[target]}"
                            )
                else:
                    rewrite_refs(item)
        elif isinstance(value, list):
            for item in value:
                rewrite_refs(item)

    rewrite_refs(transformed)

    local_refs: set[str] = set()

    def collect_refs(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if key == "$ref" and isinstance(item, str):
                    if item.startswith(_COMPONENT_PREFIX):
                        local_refs.add(
                            item.removeprefix(_COMPONENT_PREFIX),
                        )
                else:
                    collect_refs(item)
        elif isinstance(value, list):
            for item in value:
                collect_refs(item)

    collect_refs(transformed)
    unknown = sorted(local_refs - set(renamed))
    if unknown:
        raise RuntimeError(f"OpenAPI dangling component refs: {unknown}")
    return transformed


def _install_openapi_component_compatibility(app: FastAPI) -> None:
    original_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        generated = original_openapi()
        transformed = _isolate_openapi_component_names(generated)
        app.openapi_schema = transformed
        return transformed

    object.__setattr__(app, "openapi", openapi)


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
    app.include_router(validation_router)
    app.include_router(layer3_router)
    app.include_router(layer3_cli_router)
    app.include_router(assembly_router)
    app.include_router(management_router)
    _install_openapi_component_compatibility(app)

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
