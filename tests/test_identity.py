"""Renamed or copied locked apps are still recognised (identity.py and the guard)."""

import os
import shutil
import subprocess
import time

import psutil
import pytest

from gatekeeper import dashdata
from gatekeeper.app import open_context
from gatekeeper.guard import Guard
from gatekeeper.identity import Identifier, original_filename, sha256_file

PING = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "PING.EXE")
needs_ping = pytest.mark.skipif(not os.path.isfile(PING), reason="needs Windows' PING.EXE")


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path / "data", console=False)  # enforcing: the guard really suspends
    yield c
    c.db.close()


def _spawn(path):
    proc = subprocess.Popen([path, "-t", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.3)
    return proc


# -- identity, without processes --------------------------------------------------------------

def test_fingerprint_survives_rename_but_not_a_different_file(ctx, tmp_path):
    real = tmp_path / "tool.exe"
    real.write_bytes(b"MZ pretend program " * 100)   # no version info: only the hash can match
    identity = Identifier(ctx.db, system_dir="")
    ctx.db.add_app("tool.exe")
    identity.learn("tool.exe", str(real))
    copy = tmp_path / "harmless.exe"
    shutil.copy(real, copy)
    assert identity.match(str(copy), {"tool.exe"}) == "tool.exe"
    other = tmp_path / "other.exe"
    other.write_bytes(b"MZ some other program")
    assert identity.match(str(other), {"tool.exe"}) is None
    assert identity.match(str(copy), set()) is None       # only matches apps that are still locked


def test_unlocking_an_app_forgets_its_fingerprints(ctx, tmp_path):
    real = tmp_path / "tool.exe"
    real.write_bytes(b"MZ pretend program")
    ctx.db.add_app("tool.exe")
    Identifier(ctx.db).learn("tool.exe", str(real))
    assert ctx.db.fingerprint_name(sha256_file(str(real))) == "tool.exe"
    dashdata.remove_app(ctx, "tool.exe")
    assert ctx.db.fingerprint_name(sha256_file(str(real))) is None


def test_programs_in_the_windows_folder_are_skipped(ctx):
    identity = Identifier(ctx.db, system_dir=r"C:\Windows" + os.sep)
    assert identity.is_system(r"C:\Windows\System32\cmd.exe")
    assert identity.match(r"C:\Windows\System32\cmd.exe", {"cmd.exe"}) is None
    assert not identity.is_system(r"C:\Users\me\Downloads\chrome.exe")


def test_locking_by_browsing_fingerprints_the_file(ctx, tmp_path):
    exe = tmp_path / "Game.exe"
    exe.write_bytes(b"MZ game")
    name, error = dashdata.lock_app(ctx, str(exe))
    assert (name, error) == ("game.exe", "") and ctx.db.fingerprint_name(sha256_file(str(exe))) == "game.exe"


@needs_ping
def test_original_filename_is_read_from_version_info():
    assert original_filename(PING) == "ping.exe"   # stored as "PING.EXE.MUI"; normalized


# -- the guard, with real processes -----------------------------------------------------------

@needs_ping
def test_guard_freezes_a_renamed_copy(ctx, tmp_path):
    copy = tmp_path / "notping.exe"
    shutil.copy(PING, copy)
    ctx.db.add_app("ping.exe")
    victim = _spawn(str(copy))
    requested = []
    guard = Guard(ctx, requested.append)
    try:
        guard.scan()
        assert requested == ["ping.exe"]
        assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED
        blocked = dashdata.query_events(ctx.db, event="blocked")[0]["detail"]
        assert blocked.startswith("ping.exe ") and "renamed copy: notping.exe" in blocked
        guard.resolve("ping.exe", False)
        assert victim.wait(timeout=5) is not None    # denied: the copy is killed like the real app
    finally:
        victim.kill()
        guard.stop()


@needs_ping
def test_guard_learns_the_fingerprint_of_the_real_app(ctx):
    ctx.db.add_app("ping.exe")
    victim = _spawn(PING)
    guard = Guard(ctx, lambda n: None)
    try:
        guard.scan()
        assert ctx.db.fingerprint_name(sha256_file(PING)) == "ping.exe"
    finally:
        victim.kill()
        guard.stop()


@needs_ping
def test_unlocked_programs_are_left_alone(ctx, tmp_path):
    copy = tmp_path / "notping.exe"
    shutil.copy(PING, copy)
    ctx.db.add_app("notepad.exe")                    # something else is locked, not ping
    victim = _spawn(str(copy))
    requested = []
    guard = Guard(ctx, requested.append)
    try:
        guard.scan()
        assert requested == [] and psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
    finally:
        victim.kill()
        guard.stop()
