"""Regression tests for the security fixes and bug fixes from the code review."""

import gc
import sqlite3
import time
import tkinter as tk

import numpy as np
import pytest

from gatekeeper import auth, cli, dashdata
from gatekeeper.app import open_context
from gatekeeper.audit import TAIL
from gatekeeper.dashboard import Dashboard
from gatekeeper.dashdata import SingleInstance
from gatekeeper.faces import Face
from gatekeeper.matcher import FaceMatcher, FaceUnlock, LiveMatch
from gatekeeper.ui import UnlockPrompt

PASSWORD = "correct horse battery"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(True, tmp_path, console=False)
    yield c
    c.db.close()


# -- audit log: incremental verification and the seal ------------------------------------------

def test_deleting_the_seal_is_detected(ctx):
    for i in range(3):
        ctx.audit.record("e", str(i))
    assert ctx.audit.verify() == (True, None)
    ctx.audit.seal_path.unlink()
    assert ctx.audit.verify() == (False, TAIL)


def test_empty_log_without_seal_is_fine(tmp_path):
    c = open_context(True, tmp_path, console=False)
    try:
        assert c.audit.verify() == (True, None)
    finally:
        c.db.close()


def test_incremental_verify_still_checks_new_rows(ctx):
    ctx.audit.record("a")
    assert ctx.audit.verify() == (True, None)   # caches the verified prefix
    ctx.audit.record("b")
    ctx.audit.record("c")
    assert ctx.audit.verify() == (True, None)   # only b and c were hashed, and they verify


def test_edit_through_another_connection_is_detected_after_caching(ctx):
    for i in range(4):
        ctx.audit.record("e", str(i))
    assert ctx.audit.verify() == (True, None)
    other = sqlite3.connect(str(ctx.directory / "gatekeeper.db"))  # e.g. someone with a DB editor
    with other:
        other.execute("UPDATE audit_log SET detail='edited' WHERE id=2")
    other.close()
    assert ctx.audit.verify() == (False, 2)


def test_edit_through_our_own_connection_is_detected_after_caching(ctx):
    for i in range(4):
        ctx.audit.record("e", str(i))
    assert ctx.audit.verify() == (True, None)
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("UPDATE audit_log SET detail='edited' WHERE id=1")
    assert ctx.audit.verify() == (False, 1)


# -- log filters -------------------------------------------------------------------------------

def test_severity_filter_runs_before_the_limit(ctx):
    ctx.audit.record("bad_password", "old")
    for i in range(10):
        ctx.audit.record("unlocked", f"x{i}.exe")  # newer, and not a problem
    rows = dashdata.query_events(ctx.db, limit=3, severity="bad")
    assert [r["event"] for r in rows] == ["bad_password"]  # used to be [] (filtered after LIMIT 3)


def test_day_filter_covers_the_whole_local_day(ctx):
    from datetime import date
    ctx.audit.record("unlocked", "x.exe")
    assert len(dashdata.query_events(ctx.db, day=date.today())) == 1


# -- CLI release ------------------------------------------------------------------------------

def test_release_needs_the_password_while_a_guard_is_running(ctx, monkeypatch, capsys):
    auth.set_password(ctx.db, PASSWORD)
    guard = SingleInstance(ctx.directory)
    assert guard.acquire()  # stands in for the running dashboard/guard
    try:
        monkeypatch.setattr("getpass.getpass", lambda *_a: "wrong password")
        assert cli.cmd_release(ctx, None) == 1
        monkeypatch.setattr("getpass.getpass", lambda *_a: PASSWORD)
        assert cli.cmd_release(ctx, None) == 0
    finally:
        guard.release()


def test_release_needs_no_password_when_no_guard_runs(ctx, monkeypatch):
    def no_prompt(*_a):
        raise AssertionError("should not ask for a password")

    monkeypatch.setattr("getpass.getpass", no_prompt)
    assert cli.cmd_release(ctx, None) == 0


def test_cli_add_uses_the_dashboard_validation(ctx, monkeypatch):
    auth.set_password(ctx.db, PASSWORD)
    monkeypatch.setattr("getpass.getpass", lambda *_a: PASSWORD)

    class Args:
        name = r'"C:\Program Files\App\Chrome.EXE"'

    assert cli.cmd_add(ctx, Args) == 0 and ctx.db.list_apps() == ["chrome.exe"]
    Args.name = "taskmgr"
    assert cli.cmd_add(ctx, Args) == 1 and ctx.db.list_apps() == ["chrome.exe"]


# -- face matching ---------------------------------------------------------------------------

class DeadCamera:
    def read(self):
        return False, None

    def release(self):
        pass


class OneFace:
    def detect(self, frame):
        return [Face((0, 0, 200, 200), 0.99, np.zeros(15))]

    def embed(self, frame, face):
        return np.ones(128, np.float32)


def test_dead_camera_gives_up_instead_of_spinning():
    live = LiveMatch(FaceMatcher(OneFace(), [np.ones(128, np.float32)], 0.45), DeadCamera, timeout=30)
    unlock = FaceUnlock(live)
    started = time.monotonic()
    unlock.start()
    unlock._thread.join(10)
    assert unlock.state == "unavailable" and time.monotonic() - started < 10


# -- GUI (needs a display) --------------------------------------------------------------------

@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass
    gc.collect()  # free Tk objects on the main thread (see test_dashboard_smoke)


def pump(root, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        root.update()
        time.sleep(0.02)


class MatchedFace:
    state, best = "idle", 0.9

    def start(self):
        self.state = "matched"

    def cancel(self):
        pass


def test_escape_during_the_face_checkmark_does_not_deny(root):
    results = []
    prompt = UnlockPrompt(root, "x.exe", lambda pw: False, results.append, face=MatchedFace(), fullscreen=False)
    pump(root, 0.4)               # face matched; the checkmark is playing
    assert prompt.closing and results == []
    prompt._cancel()              # Escape / Cancel / Alt+F4 while it plays
    pump(root, 1.4)
    assert results == [True]      # the unlock still goes through


class FakeRuntime:
    running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def test_protection_never_starts_without_a_password(ctx, root):
    runtime = FakeRuntime()
    app = Dashboard(ctx, root=root, runtime=runtime)
    app.toggle_protection()
    assert runtime.running is False
    auth.set_password(ctx.db, PASSWORD)
    app.toggle_protection()
    assert runtime.running is True
