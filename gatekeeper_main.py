"""Entry script for the PyInstaller build (gatekeeper.spec): same as `python -m gatekeeper`."""

import sys

from gatekeeper.cli import main

sys.exit(main())
