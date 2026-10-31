"""`python -m gatekeeper ...` entry point."""

import sys

from .cli import main

sys.exit(main())  # the command's return value becomes the process exit code
