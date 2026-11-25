"""PyInstaller entry point for the Windows portable runtime."""

from __future__ import annotations

from event_switch_manager.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
