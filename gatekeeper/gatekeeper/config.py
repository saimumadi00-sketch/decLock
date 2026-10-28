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


def data_dir(override=None, dev=False) -> Path:
    """Dev mode uses a separate directory so it never touches real settings."""
    if override:
        path = Path(override)
    else:
        env = os.environ.get("GATEKEEPER_DATA_DIR")
        base = Path(env) if env else Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
        path = base.with_name(base.name + "-dev") if dev and not env else base
    path.mkdir(parents=True, exist_ok=True)
    return path


def setup_logging(directory: Path, dev: bool, console: bool = True) -> None:
    root = logging.getLogger("gatekeeper")
    root.setLevel(logging.DEBUG if dev else logging.INFO)
    if root.handlers:
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
