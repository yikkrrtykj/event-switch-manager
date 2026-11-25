import argparse
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from .app import create_app
from .database import create_database_engine, upgrade_database
from .settings import (
    LOOPBACK,
    Settings,
    default_database_path,
    default_web_dist,
)


def _ensure_loopback_port_available(port: int) -> None:
    """Fail safely without touching another process that owns the port."""
    deadline = time.monotonic() + 2
    last_error: OSError | None = None
    while True:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((LOOPBACK, port))
            return
        except OSError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"Port {port} is unavailable on {LOOPBACK}; close the other "
                    "process or choose a different --port. No other process was "
                    "stopped."
                ) from last_error
            time.sleep(0.05)
        finally:
            probe.close()


def _prepare_database(settings: Settings) -> None:
    """Apply migrations before binding, but never delete an existing database."""
    engine = create_database_engine(settings.database_path)
    try:
        upgrade_database(engine)
    finally:
        engine.dispose()


def _open_when_ready(server: uvicorn.Server, url: str) -> None:
    deadline = time.monotonic() + 30
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.1)
    if server.started:
        webbrowser.open(url)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Event Switch Manager on IPv4 loopback")
    parser.add_argument("--database", type=Path, default=default_database_path())
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--web-dist", type=Path, default=default_web_dist())
    parser.add_argument("--dev", action="store_true", help="Allow the local Vite proxy host")
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the local browser automatically (portable smoke tests)",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        _ensure_loopback_port_available(args.port)
    except RuntimeError as exc:
        print(f"Event Switch Manager cannot start: {exc}", file=sys.stderr)
        return 1
    settings = Settings(
        database_path=args.database,
        port=args.port,
        web_dist=args.web_dist,
        development=args.dev,
    )
    try:
        _prepare_database(settings)
    except Exception as exc:
        print(
            f"Event Switch Manager cannot prepare database "
            f"{settings.database_path}: {exc}",
            file=sys.stderr,
        )
        return 1
    try:
        app = create_app(settings)
    except Exception as exc:
        print(f"Event Switch Manager cannot start: {exc}", file=sys.stderr)
        return 1
    config = uvicorn.Config(
        app,
        host=LOOPBACK,
        port=settings.port,
        proxy_headers=False,
    )
    server = uvicorn.Server(config)
    if not args.no_browser and getattr(sys, "frozen", False):
        threading.Thread(
            target=_open_when_ready,
            args=(server, settings.url),
            daemon=True,
            name="esm-open-browser",
        ).start()
    try:
        server.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
