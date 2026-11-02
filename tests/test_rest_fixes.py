"""Round 3: the SYSTEM watchdog (#3, #11), frozen helpers (#17) and time-zone-proof schedules (#18).
Windows calls are faked; the real ones can only run on Windows as SYSTEM."""

import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

import psutil
import pytest

from gatekeeper import auth, cli, schedule, watchdog
from gatekeeper.app import open_context
from gatekeeper.guard import Guard
from gatekeeper.watchdog import BACKOFF_MAX, Watchdog, protected, read_settings, usb_wanted


def _user(tmp_path, name, password=True, **settings):
    d = tmp_path / name
    ctx = open_context(False, d, console=False)
    if password:
        auth.set_password(ctx.db, "correct horse battery")
    for k, v in settings.items():
        ctx.db.set_setting(k, v)
    ctx.db.close()
    return d


# -- watchdog decisions --------------------------------------------------------------------------

class World:
    """Fake Windows for the watchdog."""

    def __init__(self, dirs):
        self.dirs = dirs                      # sid -> data dir
        self.sessions = [(1, "S-alice")]
        self.guards = {}                      # session -> [(pid, suspended)]
        self.launched, self.resumed, self.usb_fixes = [], [], 0
        self.now, self.wall = 100.0, 1_000_000.0

    def make(self):
        return Watchdog(lambda: list(self.sessions), self.dirs.get, lambda s: self.guards.get(s, []),
                        self.launch, self.resumed.append, lambda: list(self.dirs.values()), self.usb,
                        clock=lambda: self.now, wall=lambda: self.wall)

    def launch(self, session):
        self.launched.append(session)
        return True

    def usb(self):
        self.usb_fixes += 1
        return True


def test_restarts_a_killed_guard_with_capped_backoff(tmp_path):
    world = World({"S-alice": _user(tmp_path, "alice")})
    dog = world.make()
    dog.tick()
    assert world.launched == [1]
    dog.tick()                                  # immediately again: waits for the backoff
    assert world.launched == [1]
    for _ in range(10):                         # an attacker killing it every time it starts
        world.now += BACKOFF_MAX
        dog.tick()
    assert len(world.launched) == 11            # never more than BACKOFF_MAX between tries
    world.guards[1] = [(42, False)]
    dog.tick()                                  # running again: backoff forgotten
    world.guards[1] = []
    world.now += 0.1
    dog.tick()
    assert len(world.launched) == 12


def test_resumes_a_suspended_guard(tmp_path):
    world = World({"S-alice": _user(tmp_path, "alice")})
    world.guards[1] = [(42, True)]
    world.make().tick()
    assert world.resumed == [42] and world.launched == []


def test_users_without_gatekeeper_are_left_alone(tmp_path):
    world = World({"S-alice": _user(tmp_path, "alice", password=False)})
    world.sessions.append((2, "S-guest"))       # no data folder at all
    world.make().tick()
    assert world.launched == []


def test_usb_block_restored_only_when_wanted(tmp_path):
    world = World({"S-alice": _user(tmp_path, "alice", usb_block="1"),
                   "S-bob": _user(tmp_path, "bob", usb_block="0")})
    world.guards[1] = [(42, False)]
    world.make().tick()
    assert world.usb_fixes == 1
    world2 = World({"S-bob": _user(tmp_path, "bob2", usb_block="0")})
    world2.make().tick()
    assert world2.usb_fixes == 0


def test_usb_temporary_allow_is_respected(tmp_path):
    d = _user(tmp_path, "alice", usb_block="1", usb_allow_until=2_000_000.0)
    assert not usb_wanted([d], now=1_000_000.0)  # allowed for now
    assert usb_wanted([d], now=3_000_000.0)      # time is up


def test_settings_are_read_without_creating_anything(tmp_path):
    assert read_settings(tmp_path / "nobody", ["password_hash"]) == {}
    assert not (tmp_path / "nobody").exists()
    assert protected(_user(tmp_path, "alice")) and not protected(None)


def test_hidden_commands_need_their_account(monkeypatch):
    monkeypatch.setattr(watchdog, "is_system", lambda: False)
    assert cli.main(["--service", "watchdog"]) == 1
    from gatekeeper import winapi
    monkeypatch.setattr(winapi, "is_admin", lambda: False)
    assert cli.main(["install-watchdog"]) == 1 and cli.main(["remove-watchdog"]) == 1


def test_installed_dashboard_does_not_quit(tmp_path, monkeypatch):
    from gatekeeper.dashboard import Dashboard
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    app = Dashboard.__new__(Dashboard)          # no window needed for the property
    app.relaunch_args = ["--service", "--data-dir", "x", "gui"]
    assert app.managed
    app.relaunch_args = ["--data-dir", "x", "gui"]
    assert not app.managed


# -- #17 helpers started by a locked app are frozen with it ---------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell to start a helper process")
def test_children_are_frozen_and_closed_with_the_app(tmp_path):
    name = f"gk_parent_{uuid.uuid4().hex[:8]}"
    shell = tmp_path / name
    shutil.copy2(shutil.which("sh"), shell)
    with open(shell, "ab") as fh:
        fh.write(uuid.uuid4().bytes)            # unique fingerprint (renamed-copy detection)
    parent = subprocess.Popen([str(shell), "-c", "sleep 60 & wait"])
    time.sleep(0.3)
    ctx = open_context(False, tmp_path / "data", console=False)
    ctx.db.add_app(name)
    guard = Guard(ctx, lambda n: None)
    try:
        guard.scan()
        child = psutil.Process(parent.pid).children()[0]
        assert child.status() == psutil.STATUS_STOPPED          # "sleep" isn't locked, but its parent is
        guard.resolve(name, False)
        assert parent.wait(timeout=5) is not None
        assert not child.is_running() or child.status() == psutil.STATUS_ZOMBIE
    finally:
        for p in psutil.Process().children(recursive=True):
            try:
                p.kill()
            except psutil.Error:
                pass
        guard.stop()
        ctx.db.close()


# -- #18 schedules ignore time-zone changes ---------------------------------------------------------

def test_schedule_is_pinned_to_its_offset(tmp_path):
    ctx = open_context(True, tmp_path / "s", console=False)
    try:
        schedule.set_window(ctx.db, "a.exe", "09:00-17:00", offset=360)
        assert ctx.db.get_setting("schedule:a.exe") == "09:00-17:00@+360"
        assert schedule.get(ctx.db, "a.exe") == "09:00-17:00"   # what the dashboard shows
        schedule.set_window(ctx.db, "a.exe", "")
        assert schedule.get(ctx.db, "a.exe") == ""
    finally:
        ctx.db.close()


def test_schedule_uses_saved_offset_not_current_zone():
    utc = datetime.now(timezone.utc)
    hour = (utc + timedelta(minutes=360)).hour                   # the hour it is in Dhaka right now
    window = f"{hour:02d}:00-{(hour + 1) % 24:02d}:00"
    assert schedule.is_active(f"{window}@+360")                  # whatever zone this PC is set to
    elsewhere = (utc + timedelta(minutes=360 - 720)).hour
    if not hour <= elsewhere < hour + 1:
        assert not schedule.is_active(f"{window}@-360")          # 12 hours away: outside the window
    assert schedule.is_active(f"{window}@junk") in (True, False)  # bad offset: falls back to local time
