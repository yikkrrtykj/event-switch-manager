"""Source-tree compatibility launcher.

The packaged artifact uses two dedicated entry points:
  * EventSwitchManager-ConsoleLab.exe      (windowed GUI)
  * EventSwitchManager-ConsoleLab-CLI.exe  (console diagnostics)
"""

from __future__ import annotations

import sys


def main() -> int:
    args = list(sys.argv[1:])
    if not args or args[0] == "--gui-smoke":
        from event_switch_manager.lab_runner.gui import main as gui_main

        return gui_main(args)
    from event_switch_manager.lab_runner.cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
