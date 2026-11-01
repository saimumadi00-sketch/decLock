"""Constants, the data-folder location and logging setup."""

import logging
import logging.handlers
import os
import sys
from pathlib import Path

APP_NAME = "Gatekeeper"
MIN_PASSWORD_LEN = 8

# Never lockable: locking these could make the machine unusable or lock out
# the tool itself.
PROTECTED_PROCESSES = frozenset({
    "explorer.exe", "winlogon.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "smss.exe", "svchost.exe", "dwm.exe", "taskmgr.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "regedit.exe",
    "python.exe", "pythonw.exe", "gatekeeper.exe", "system", "registry",
})


DATA_DIR_ENV = "GATEKEEPER_DATA_DIR"


def env_data_dir(environ=None, frozen=None):
    """$GATEKEEPER_DATA_DIR, or None. Ignored in an installed (frozen) build.

    Any program running as the user can set this variable for the next logon (HKCU\\Environment).
    If the installed guard obeyed it, it would start on an empty folder, show the "choose a
    password" screen and lock nothing, so a stray or planted value could switch protection off.
    Development checkouts keep honouring it; an installed copy only moves with --data-dir, which
    sits in the admin-owned startup shortcut."""
    environ = os.environ if environ is None else environ
    frozen = bool(getattr(sys, "frozen", False)) if frozen is None else frozen
    return None if frozen else (environ.get(DATA_DIR_ENV) or None)


def data_dir_env_ignored(environ=None, frozen=None) -> bool:
    """True when the variable is set but env_data_dir() refused it (worth an audit entry)."""
    environ = os.environ if environ is None else environ
    return bool(environ.get(DATA_DIR_ENV)) and env_data_dir(environ, frozen) is None


def data_dir(override=None, dev=False, environ=None, frozen=None) -> Path:
    """Folder holding the database, key, seal and logs (created if missing).

    Order: explicit --data-dir, then $GATEKEEPER_DATA_DIR (development only, see env_data_dir),
    then %APPDATA%\\Gatekeeper. Dev mode uses a separate directory so it never touches real settings."""
    environ = os.environ if environ is None else environ
    if override:
        path = Path(override)
    else:
        env = env_data_dir(environ, frozen)
        base = Path(env) if env else Path(environ.get("APPDATA", Path.home())) / APP_NAME
        path = base.with_name(base.name + "-dev") if dev and not env else base
    path.mkdir(parents=True, exist_ok=True)
    return path


def setup_logging(directory: Path, dev: bool, console: bool = True) -> None:
    """Rotating gatekeeper.log (3 x 1 MB) plus, optionally, the console. Safe to call twice."""
    root = logging.getLogger("gatekeeper")
    root.setLevel(logging.DEBUG if dev else logging.INFO)
    if root.handlers:  # already configured (e.g. a second open_context in the same process)
        return
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(
        directory / "gatekeeper.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)
    if console and sys.stderr is not None:  # windowed builds have no stderr
        stream = logging.StreamHandler()
        stream.setFormatter(fmt)
        root.addHandler(stream)
