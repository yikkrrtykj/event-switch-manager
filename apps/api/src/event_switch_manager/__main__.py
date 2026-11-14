import argparse
from pathlib import Path

import uvicorn

from .app import create_app
from .settings import LOOPBACK, Settings, default_database_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Event Switch Manager on IPv4 loopback")
    parser.add_argument("--database", type=Path, default=default_database_path())
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--web-dist", type=Path, default=Path("apps/web/dist"))
    parser.add_argument("--dev", action="store_true", help="Allow the local Vite proxy host")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    settings = Settings(
        database_path=args.database,
        port=args.port,
        web_dist=args.web_dist,
        development=args.dev,
    )
    uvicorn.run(create_app(settings), host=LOOPBACK, port=settings.port, proxy_headers=False)


if __name__ == "__main__":
    main()
