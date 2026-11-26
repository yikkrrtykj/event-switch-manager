"""PyInstaller entry point for the isolated ConsoleLab artifact."""

from __future__ import annotations

from event_switch_manager.lab_runner.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
