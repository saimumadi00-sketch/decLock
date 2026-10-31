"""Dev-mode resolution.

Dev mode disables every destructive action (process killing, USB blocking,
screen locking) and only logs what would have happened, so development can
never lock the developer out.

It is enabled with `--dev` or `GATEKEEPER_DEV=1`. It is refused when running
as the installed service (`--service`), and the environment variable is also
ignored-with-error in a frozen (PyInstaller) build, so a stray variable can
never silently weaken an installed copy.
"""

import os
import sys

ENV_VAR = "GATEKEEPER_DEV"


class DevModeRefused(RuntimeError):
    pass


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resolve_dev_mode(cli_dev: bool = False, service: bool = False, environ=None) -> bool:
    environ = os.environ if environ is None else environ
    env_dev = environ.get(ENV_VAR) == "1"
    if service and (cli_dev or env_dev):
        raise DevModeRefused("Dev mode is refused when running as the installed service.")
    if env_dev and is_frozen():
        raise DevModeRefused(f"{ENV_VAR}=1 is refused in an installed (frozen) build.")
    return cli_dev or env_dev
