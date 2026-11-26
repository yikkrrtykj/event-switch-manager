"""Module entry point: same default GUI / diagnostic CLI routing as the EXE."""

from __future__ import annotations

import sys


def main() -> int:
    args = list(sys.argv[1:])
    if not args or args[0] == "--gui-smoke":
        from .gui import main as gui_main

        return gui_main(args)
    from .cli import main as cli_main

    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
