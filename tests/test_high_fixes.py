"""High-severity fixes: deleted data can't reopen first-run setup, and open apps lock again."""

import os
import subprocess
import sys
import time

import psutil
import pytest

from gatekeeper import auth, cli, dashdata
from gatekeeper.app import open_context
from gatekeeper.enrolment import BLOCKED_MESSAGE, Enrolment, setup_blocked, sync
from gatekeeper.guard import Guard
from gatekeeper.idle import PRESENT_SECONDS, REASK_SECONDS, Relocker

PASSWORD = "correct horse battery"


# -- enrolment markers (#2) -------------------------------------------------------------------------

@pytest.fixture
def folder(tmp_path):
    f = tmp_path / "ProgramData" / "Gatekeeper" / "enrolled"
    f.mkdir(parents=True)  # what the installer creates
    return f


@pytest.fixture
def ctx(tmp_path, folder):
    c = open_context(True, tmp_path / "appdata", console=False)
    c.enrolment = Enrolment(folder, sid="S-1-5-21-test-1001")
    yield c
    c.db.close()


def test_inactive_without_installer_folder(tmp_path):
    e = Enrolment(tmp_path / "missing", sid="S-1")
    assert not e.active and not e.mark() and not e.enrolled()
    assert not Enrolment(frozen=False).active  # development checkouts never use markers


def test_mark_is_idempotent(folder):
    e = Enrolment(folder, sid="S-1-5-21-x")
    assert e.mark() and e.mark()
    assert e.enrolled() and (folder / "S-1-5-21-x").is_file()


def test_first_setup_records_marker(ctx, folder):
    assert dashdata.create_password(ctx, PASSWORD, PASSWORD) == (True, "")
    assert ctx.enrolment.enrolled()


def test_deleted_data_blocks_new_setup(tmp_path, folder):
    enrolment = Enrolment(folder, sid="S-1-5-21-test-1001")
    first = open_context(True, tmp_path / "a", console=False)
    first.enrolment = enrolment
    assert dashdata.create_password(first, PASSWORD, PASSWORD)[0]
    first.db.close()
    # Someone deletes %APPDATA%\Gatekeeper: a brand-new, empty store appears.
    fresh = open_context(True, tmp_path / "b", console=False)
    fresh.enrolment = enrolment
    try:
        assert setup_blocked(fresh.db, enrolment)
        ok, message = dashdata.create_password(fresh, "attacker pw 1", "attacker pw 1")
        assert not ok and message == BLOCKED_MESSAGE
        assert not auth.has_password(fresh.db)
        assert dashdata.query_events(fresh.db, event="setup_blocked")
    finally:
        fresh.db.close()


def test_other_users_are_not_blocked(ctx, folder):
    Enrolment(folder, sid="S-1-5-21-someone-else").mark()
    assert not setup_blocked(ctx.db, ctx.enrolment)
    assert dashdata.create_password(ctx, PASSWORD, PASSWORD)[0]


def test_sync_marks_existing_installs(ctx):
    auth.set_password(ctx.db, PASSWORD)  # set up before markers existed
    assert not ctx.enrolment.enrolled()
    sync(ctx.db, ctx.enrolment)
    assert ctx.enrolment.enrolled()


def test_cli_init_refuses_when_blocked(ctx, monkeypatch, capsys):
    ctx.enrolment.mark()
    monkeypatch.setattr("getpass.getpass", lambda *_: pytest.fail("must not ask for a new password"))
    assert cli.cmd_init(ctx, None) == 1
    assert "blocked" in capsys.readouterr().out


def test_dashboard_shows_refusal(ctx):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from gatekeeper.dashboard import Dashboard

    class Runtime:
        running = False

        def start(self):
            pytest.fail("protection must not start from a refused setup")

        def stop(self):
            pass

    ctx.enrolment.mark()
    app = Dashboard(ctx, root=root, runtime=Runtime())
    try:
        app.start()
        root.update()
        assert getattr(app, "setup_blocked_shown", False)
        assert not hasattr(app, "setup_submit")
    finally:
        app.shutdown()
        root.destroy()


# -- re-locking apps that are already open (#4) -----------------------------------------------------

def _app(tmp_path):
    """A harmless long-running program, copied under a unique name so no other process matches it."""
    import shutil
    import uuid
    if sys.platform == "win32":
        source, args, suffix = shutil.which("ping"), ["-n", "60", "127.0.0.1"], ".exe"
    else:
        source, args, suffix = shutil.which("sleep"), ["60"], ""
    name = f"gk_test_{uuid.uuid4().hex[:8]}{suffix}"
    target = tmp_path / name
    shutil.copy2(source, target)
    with open(target, "ab") as fh:  # a unique fingerprint too: the guard also matches copies by hash
        fh.write(uuid.uuid4().bytes)
    return [str(target)] + args, name.lower()


@pytest.fixture
def live(tmp_path):
    c = open_context(False, tmp_path / "live", console=False)  # enforcing: really suspends
    yield c
    c.db.close()


@pytest.fixture
def spawn(tmp_path):
    procs = []
    cmd, name = _app(tmp_path)

    def start():
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        time.sleep(0.2)
        return p, name
    yield start
    for p in procs:
        try:
            psutil.Process(p.pid).resume()
        except psutil.Error:
            pass
        p.kill()


def _stopped(pid):
    return psutil.Process(pid).status() == psutil.STATUS_STOPPED


def test_relock_freezes_open_app_and_holds_it(live, spawn):
    proc, name = spawn()
    asked = []
    guard = Guard(live, asked.append)
    live.db.add_app(name)
    guard._granted[name] = time.monotonic() + 600  # as if it was unlocked a moment ago
    guard._seen.add((proc.pid, psutil.Process(proc.pid).create_time()))
    guard.scan()
    assert not _stopped(proc.pid)  # unlocked: runs freely

    guard.relock("Windows locked")
    guard.scan()
    assert _stopped(proc.pid)
    assert asked == []                    # no prompt while nobody is there
    assert guard.held() == [name]

    guard.reprompt_held()                 # the user is back
    assert asked == [name]
    guard.resolve(name, False)            # cancelled / wrong / timed out
    assert proc.poll() is None and _stopped(proc.pid)  # still alive, still frozen: never killed
    assert guard.held() == [name]

    guard.resolve(name, True)
    assert not _stopped(proc.pid) and guard.held() == []
    assert dashdata.query_events(live.db, event="held")
    assert dashdata.query_events(live.db, event="relocked")
    guard.stop()


def test_relock_cancels_unlock_grant(live, spawn):
    _first, name = spawn()
    live.db.add_app(name)
    guard = Guard(live, lambda n: None)
    guard.scan()
    guard.resolve(name, True)             # unlock: grants new copies for 10 minutes
    second, _ = spawn()
    guard.scan()
    assert not _stopped(second.pid)
    guard.relock("idle")
    third, _ = spawn()
    guard.scan()
    assert _stopped(third.pid) and _stopped(second.pid)
    guard.stop()
    assert not _stopped(third.pid)        # shutdown always releases


def test_new_launch_is_still_killed_on_deny(live, spawn):
    proc, name = spawn()
    live.db.add_app(name)
    asked = []
    guard = Guard(live, asked.append)
    guard.scan()
    assert asked == [name]
    guard.resolve(name, False)
    assert proc.wait(timeout=5) is not None  # ordinary launches keep the old behaviour
    guard.stop()


def test_relock_mid_prompt_does_not_double_freeze(live, spawn):
    proc, name = spawn()
    live.db.add_app(name)
    guard = Guard(live, lambda n: None)
    guard.scan()                          # frozen, prompt open
    guard.relock("Windows locked")
    guard.scan()
    assert len(guard._pending[name]) == 1  # not queued (or suspended) a second time
    guard.resolve(name, True)
    assert not _stopped(proc.pid)          # one resume is enough
    guard.stop()


class FakeGuard:
    def __init__(self):
        self.reasons = []

    def relock(self, reason):
        self.reasons.append(reason)


def test_relocker_triggers():
    guard, state = FakeGuard(), {"locked": False, "idle": 0.0, "now": 0.0, "minutes": 10.0}
    r = Relocker(guard, lambda: state["minutes"], idle_fn=lambda: state["idle"],
                 locked_fn=lambda: state["locked"], clock=lambda: state["now"])
    r.tick()
    assert guard.reasons == []
    state["locked"] = True
    r.tick()
    r.tick()
    assert guard.reasons == ["Windows locked"]          # once per lock
    state["locked"] = False
    state["idle"] = 600
    r.tick()
    r.tick()
    assert guard.reasons[-1].startswith("idle") and len(guard.reasons) == 2  # once per idle stretch
    state["idle"] = 1
    r.tick()
    state["minutes"], state["idle"] = 0, 10_000          # 0 = only when Windows locks
    r.tick()
    assert len(guard.reasons) == 2


def test_relocker_reasks_only_when_present():
    state = {"locked": False, "idle": 0.0, "now": 100.0}
    r = Relocker(FakeGuard(), lambda: 10, idle_fn=lambda: state["idle"],
                 locked_fn=lambda: state["locked"], clock=lambda: state["now"])
    assert r.may_ask()
    r.asked()
    assert not r.may_ask()                                # cooling down after a refusal
    state["now"] += REASK_SECONDS
    assert r.may_ask()
    state["idle"] = PRESENT_SECONDS + 1
    assert not r.may_ask()                                # nobody touching the PC
    state["idle"], state["locked"] = 0, True
    assert not r.may_ask()                                # lock screen showing


def test_relock_setting(ctx):
    assert dashdata.relock_minutes(ctx.db) == 10
    assert dashdata.set_relock_minutes(ctx, "0") == 0
    with pytest.raises(ValueError):
        dashdata.set_relock_minutes(ctx, "-3")
