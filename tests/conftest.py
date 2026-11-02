"""Shared pytest setup.

pytest puts tmp_path under %TEMP%, which on Windows is inside %LOCALAPPDATA%. Folder lock refuses
to lock anything in AppData (on purpose, see folders.validate), so the folder-lock tests would fail
on a plain `pytest` run. When the default temp root is in such a protected place, tmp_path is moved
to <repo>/.pytest_tmp instead. An explicit --basetemp (or PYTEST_DEBUG_TEMPROOT) is always respected.
"""

import os
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FALLBACK = REPO / ".pytest_tmp"  # pytest empties --basetemp on each run, so it must be dedicated to tests


def _protected(path: Path) -> bool:
    """Is `path` somewhere folder lock refuses (AppData, Windows, Program Files, ProgramData)?"""
    from gatekeeper.folders import _no_go_trees
    target = os.path.normcase(os.path.abspath(path))
    for tree in _no_go_trees():
        t = os.path.normcase(os.path.abspath(tree)).rstrip("\\/")
        if target == t or target.startswith(t + os.sep):
            return True
    return False


def pytest_configure(config):
    if config.option.basetemp:
        return  # the caller chose a folder
    root = Path(os.environ.get("PYTEST_DEBUG_TEMPROOT") or tempfile.gettempdir())
    if _protected(root) and not _protected(FALLBACK):
        config.option.basetemp = str(FALLBACK)
