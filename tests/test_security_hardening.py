"""Security hardening round: the watchdog can't be fooled into leaving protection off, the guard
can't be kept from starting, `release` can't skip the password, and the ProgramData witness can't be
silenced or polluted by files someone else added. Windows-only calls are faked where needed."""

import argparse
import json
import os
import sys
import time

import pytest

from gatekeeper import auth, cli, dashdata, watchdog
from gatekeeper.app import open_context
from gatekeeper.audit import AuditLog
from gatekeeper.db import Database
from gatekeeper.enrolment import ADMINS, Enrolment, file_owner_sid, setup_blocked
from gatekeeper.logwitness import FUTURE_SLACK, LogWitness
from gatekeeper.watchdog import MAX_MISSES, Watchdog, canonical_guard_args, protected

PASSWORD = "correct horse battery"
ME, OTHER = "S-1-5-21-owner", "S-1-5-21-other"


def _user(tmp_path, name, password=True, **settings):
    d = tmp_path / name
    ctx = open_context(False, d, console=False)
    if password:
        auth.set_password(ctx.db, PASSWORD)
    for k, v in settings.items():
        ctx.db.set_setting(k, v)
    ctx.db.close()
    return d


# -- the watchdog only counts real guards ---------------------------------------------------------

def test_canonical_guard_command_lines(tmp_path):
    own, elsewhere = tmp_path / "own", tmp_path / "elsewhere"
    own.mkdir(), elsewhere.mkdir()
    assert canonical_guard_args(["--service", "gui"], own)
    assert canonical_guard_args(["--service", "gui", "--minimized"], own)
    assert canonical_guard_args(["--service", "--data-dir", str(own), "gui"], own)  # elevated relaunch
    assert canonical_guard_args([f"--data-dir={own}", "--service", "gui"], own)
    assert canonical_guard_args(["--service", "run"], own)


@pytest.mark.parametrize("args", [
    ["--service", "face", "test"],                  # a preview window, not a guard
    ["--service", "confirm-uninstall"],
    ["--service", "watchdog"],
    ["--service", "--data-dir", "ELSEWHERE", "gui"],  # a copy pointed at another folder
    ["--service", "--data-dir"],                    # malformed
    ["gui"],                                        # not the installed service
    ["--service", "--dev", "gui"],
    ["--service", "gui", "gui"],
    ["--service", "gui", "extra"],
    [],
])
def test_non_guard_command_lines_are_refused(tmp_path, args):
    own, elsewhere = tmp_path / "own", tmp_path / "elsewhere"
    own.mkdir(), elsewhere.mkdir()
    args = [str(elsewhere) if a == "ELSEWHERE" else a for a in args]
    assert not canonical_guard_args(args, own)


def test_data_dir_must_match_even_without_expected_dir(tmp_path):
    assert not canonical_guard_args(["--service", "--data-dir", str(tmp_path), "gui"], None)


class World:
    def __init__(self, dirs, enrolled=()):
        self.dirs, self.enrolled = dirs, set(enrolled)
        self.sessions = [(1, ME)]
        self.guards, self.asked_dirs = {}, []
        self.launched, self.resumed, self.disconnected = [], [], []
        self.now = 100.0

    def guards_in(self, session, directory):
        self.asked_dirs.append(directory)
        return self.guards.get(session, [])

    def make(self, disconnect=True):
        return Watchdog(lambda: list(self.sessions), self.dirs.get, self.guards_in,
                        lambda s: self.launched.append(s) or True, self.resumed.append,
                        lambda: list(self.dirs.values()), lambda: False,
                        clock=lambda: self.now, wall=lambda: 1e9,
                        enrolled=lambda sid: sid in self.enrolled,
                        disconnect=self.disconnected.append if disconnect else None)


def test_watchdog_asks_about_the_users_own_folder(tmp_path):
    d = _user(tmp_path, "alice")
    world = World({ME: d})
    world.guards[1] = [(7, False)]
    world.make().tick()
    assert world.asked_dirs == [d] and world.launched == []


def test_missing_database_does_not_switch_the_watchdog_off(tmp_path):
    d = _user(tmp_path, "alice")
    renamed = tmp_path / "alice-hidden"
    d.rename(renamed)                               # data folder renamed away
    assert not protected(d)                         # the database alone no longer says "protected"
    assert protected(d, ME, lambda sid: sid == ME)  # but the add-only marker still does
    world = World({ME: d}, enrolled=[ME])
    world.make().tick()
    assert world.launched == [1]                    # so the guard is still restarted


def test_unenrolled_users_without_data_are_still_left_alone(tmp_path):
    world = World({ME: tmp_path / "nothing"})
    world.make().tick()
    assert world.launched == []


def test_enrolment_check_errors_do_not_crash_the_watchdog(tmp_path):
    def broken(_sid):
        raise OSError("boom")
    assert not protected(tmp_path / "nothing", ME, broken)


def test_watchdog_fails_closed_when_the_guard_never_stays_up(tmp_path):
    world = World({ME: _user(tmp_path, "alice")})
    dog = world.make()
    for _ in range(MAX_MISSES + 1):
        dog.tick()
        world.now += watchdog.BACKOFF_MAX
    assert world.disconnected == [1]
    assert len(world.launched) == MAX_MISSES         # the failing round disconnects instead of launching


def test_a_running_guard_resets_the_miss_count(tmp_path):
    world = World({ME: _user(tmp_path, "alice")})
    dog = world.make()
    for _ in range(MAX_MISSES - 1):
        dog.tick()
        world.now += watchdog.BACKOFF_MAX
    world.guards[1] = [(7, False)]
    dog.tick()                                       # it came up
    world.guards[1] = []
    for _ in range(MAX_MISSES - 1):
        dog.tick()
        world.now += watchdog.BACKOFF_MAX
    assert world.disconnected == []


def test_no_disconnect_callback_means_no_disconnect(tmp_path):
    world = World({ME: _user(tmp_path, "alice")})
    dog = world.make(disconnect=False)
    for _ in range(MAX_MISSES * 2):
        dog.tick()
        world.now += watchdog.BACKOFF_MAX
    assert len(world.launched) == MAX_MISSES * 2     # keeps trying; never errors


# -- the guard can't be kept from starting -------------------------------------------------------

class FakeLock:
    def __init__(self, free_after=None):
        self.calls, self.free_after = 0, free_after

    def acquire(self, wait=0):
        self.calls += 1
        return self.free_after is not None and self.calls > self.free_after

    def release(self):
        pass


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def test_claim_slot_takes_a_lock_that_comes_free():
    c = Clock()
    assert cli.claim_guard_slot(FakeLock(free_after=2), lambda: [1], clock=c, sleep=c.sleep) == "lock"


def test_claim_slot_guards_anyway_when_nothing_real_holds_the_lock():
    c = Clock()
    assert cli.claim_guard_slot(FakeLock(), lambda: [], clock=c, sleep=c.sleep) == "lockless"


def test_claim_slot_leaves_promptly_when_a_real_guard_runs():
    c = Clock()
    assert cli.claim_guard_slot(FakeLock(), lambda: [1], linger=4, clock=c, sleep=c.sleep) == "exit"
    assert c.t <= 4.5                               # never lingers (a lingering copy looks like a guard)


def test_claim_slot_takes_over_when_the_older_guard_dies():
    c = Clock()
    alive = {"older": True}

    def older():
        if c.t >= 1.0:
            alive["older"] = False
        return [1] if alive["older"] else []
    assert cli.claim_guard_slot(FakeLock(), older, linger=4, clock=c, sleep=c.sleep) == "lockless"


def test_lock_file_opened_without_sharing_is_held_not_a_crash(tmp_path, monkeypatch):
    def refuse(*_a, **_k):
        raise PermissionError("in use")
    monkeypatch.setattr(dashdata, "open", refuse, raising=False)
    assert dashdata.SingleInstance(tmp_path).acquire() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows byte-range locks")
def test_held_lock_byte_still_reports_held(tmp_path):
    import msvcrt
    with open(tmp_path / "gatekeeper.lock", "a+") as squat:
        squat.seek(0)
        msvcrt.locking(squat.fileno(), msvcrt.LK_NBLCK, 1)
        assert not dashdata.SingleInstance(tmp_path).acquire()


def _gui_args(service=True):
    return argparse.Namespace(service=service, minimized=True, data_dir=None, dev=False)


def test_installed_gui_guards_without_a_squatted_lock(tmp_path, monkeypatch):
    ctx = open_context(False, tmp_path / "d", console=False)
    ran = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli, "SingleInstance", lambda _d: FakeLock())
    monkeypatch.setattr(cli, "older_guards", lambda _d: [])
    monkeypatch.setattr("gatekeeper.dashboard.run_dashboard", lambda *a, **k: ran.append(k))
    try:
        assert cli.cmd_gui(ctx, _gui_args()) == 0
        assert ran, "the guard must run even though the lock is held"
        assert dashdata.query_events(ctx.db, event="lock_squatted")
    finally:
        ctx.db.close()


def test_installed_gui_exits_without_a_dialog_when_a_real_guard_runs(tmp_path, monkeypatch):
    ctx = open_context(False, tmp_path / "d", console=False)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(cli, "SingleInstance", lambda _d: FakeLock())
    monkeypatch.setattr(cli, "older_guards", lambda _d: [1234])
    monkeypatch.setattr(cli, "claim_guard_slot", lambda lock, older: "exit")
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: pytest.fail("no blocking dialog"))
    monkeypatch.setattr("gatekeeper.dashboard.run_dashboard", lambda *a, **k: pytest.fail("must not run"))
    try:
        assert cli.cmd_gui(ctx, _gui_args()) == 1
    finally:
        ctx.db.close()


def test_development_gui_keeps_the_old_behaviour(tmp_path, monkeypatch):
    ctx = open_context(False, tmp_path / "d", console=False)
    shown = []
    monkeypatch.setattr(cli, "SingleInstance", lambda _d: FakeLock())
    monkeypatch.setattr(cli, "claim_guard_slot", lambda *a: pytest.fail("dev builds don't claim"))
    monkeypatch.setattr("tkinter.messagebox.showinfo", lambda *a, **k: shown.append(a))
    try:
        assert cli.cmd_gui(ctx, _gui_args(service=False)) == 1
    finally:
        ctx.db.close()


# -- release can't skip the password -------------------------------------------------------------

@pytest.fixture
def installed_release(tmp_path, monkeypatch):
    from gatekeeper import guard, winapi
    ctx = open_context(False, tmp_path / "d", console=False)
    auth.set_password(ctx.db, PASSWORD)
    resumed = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(winapi, "is_admin", lambda: False)
    monkeypatch.setattr(guard, "release_suspended", lambda c: resumed.append(c) or 0)
    yield ctx, resumed
    ctx.db.close()


def test_installed_release_refuses_data_dir(installed_release, capsys):
    ctx, resumed = installed_release
    args = argparse.Namespace(data_dir=str(ctx.directory))
    assert cli.cmd_release(ctx, args) == 1 and resumed == []
    assert "--data-dir" in capsys.readouterr().out


def test_installed_release_always_asks(installed_release, monkeypatch):
    ctx, resumed = installed_release
    monkeypatch.setattr("getpass.getpass", lambda *_: "wrong password")
    assert cli.cmd_release(ctx, argparse.Namespace(data_dir=None)) == 1 and resumed == []
    monkeypatch.setattr("getpass.getpass", lambda *_: PASSWORD)
    assert cli.cmd_release(ctx, argparse.Namespace(data_dir=None)) == 0 and len(resumed) == 1


def test_elevated_uninstaller_release_does_not_ask(installed_release, monkeypatch):
    from gatekeeper import winapi
    ctx, resumed = installed_release
    monkeypatch.setattr(winapi, "is_admin", lambda: True)
    monkeypatch.setattr("getpass.getpass", lambda *_: pytest.fail("the hidden uninstaller can't type"))
    assert cli.cmd_release(ctx, argparse.Namespace(data_dir=None)) == 0 and len(resumed) == 1


def test_release_lock_is_given_back_after_a_refusal(installed_release, monkeypatch):
    ctx, _ = installed_release
    monkeypatch.setattr("getpass.getpass", lambda *_: "wrong password")
    cli.cmd_release(ctx, argparse.Namespace(data_dir=None))
    lock = dashdata.SingleInstance(ctx.directory)
    assert lock.acquire()
    lock.release()


# -- markers and checkpoints must be written by the user they name --------------------------------

class Owners:
    """Fake file owners: files listed in `by_other` were created by someone else."""

    def __init__(self):
        self.by_other = set()

    def __call__(self, path):
        return OTHER if os.path.basename(path) in self.by_other else ME

    def plant(self, folder, name, text=""):
        (folder / name).write_text(text, encoding="ascii")
        self.by_other.add(name)


@pytest.fixture
def folder(tmp_path):
    f = tmp_path / "ProgramData" / "Gatekeeper" / "enrolled"
    f.mkdir(parents=True)
    return f


def test_someone_elses_marker_does_not_count(folder):
    owners = Owners()
    owners.plant(folder, ME)
    assert not Enrolment(folder, sid=ME, owner_fn=owners).enrolled()


def test_squatted_marker_name_does_not_stop_enrolment(folder):
    owners = Owners()
    owners.plant(folder, ME)
    e = Enrolment(folder, sid=ME, owner_fn=owners)
    assert e.mark() and e.enrolled()
    assert [n for n in os.listdir(folder) if n.startswith(ME + ".marker.")]
    assert e.mark()                                 # idempotent: no second extra marker
    assert len([n for n in os.listdir(folder) if n.startswith(ME + ".marker.")]) == 1


def test_planted_marker_cannot_block_someone_elses_setup(tmp_path, folder):
    owners = Owners()
    owners.plant(folder, ME)                        # another user tries to lock ME out of setup
    ctx = open_context(False, tmp_path / "d", console=False)
    try:
        assert not setup_blocked(ctx.db, Enrolment(folder, sid=ME, owner_fn=owners))
    finally:
        ctx.db.close()


def test_owner_lookup_errors_are_not_trusted(folder):
    (folder / ME).write_text("")

    def broken(_p):
        raise OSError("boom")
    assert not Enrolment(folder, sid=ME, owner_fn=broken).enrolled()


def test_admin_and_system_written_markers_count(folder):
    (folder / ME).write_text("")
    assert Enrolment(folder, sid=ME, owner_fn=lambda p: ADMINS).enrolled()
    assert Enrolment(folder, sid=ME, owner_fn=lambda p: "S-1-5-18").enrolled()


@pytest.mark.skipif(os.name != "nt", reason="Windows file owners")
def test_real_owner_lookup_returns_the_creator(tmp_path):
    from gatekeeper.enrolment import current_sid
    f = tmp_path / "x"
    f.write_text("")
    assert file_owner_sid(f) in (current_sid(), ADMINS)
    assert file_owner_sid(tmp_path / "missing") is None


def _logged(tmp_path, folder, owners, now):
    db = Database(tmp_path / "g.db")
    audit = AuditLog(db, tmp_path / "audit.head")
    audit.witness = LogWitness(Enrolment(folder, sid=ME, owner_fn=owners), clock=lambda: now[0])
    for i in range(3):
        audit.record("unlocked", f"app {i}")
    return db, audit


def _rewrite_everything(db, seal_path, row_id, detail):
    """What someone with the user's rights can do: change a row and recompute every hash and the seal."""
    from gatekeeper.audit import GENESIS, _digest
    db.conn.execute("UPDATE audit_log SET detail=? WHERE id=?", (detail, row_id))
    prev, last = GENESIS, 0
    for r in db.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
        h = _digest(prev, r["ts"], r["event"], r["detail"])
        db.conn.execute("UPDATE audit_log SET prev_hash=?, hash=? WHERE id=?", (prev, h, r["id"]))
        prev, last = h, r["id"]
    db.conn.commit()
    seal_path.write_text(f"{last} {prev}", encoding="ascii")


def _fresh(audit):
    audit._verified = None
    audit.witness._cache = None


def test_future_dated_reset_is_reported(tmp_path, folder):
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, Owners(), now)
    try:
        assert audit.witness.checkpoint(db, force=True)
        _rewrite_everything(db, tmp_path / "audit.head", 2, "edited")
        _fresh(audit)
        assert not audit.verify()[0]                     # the checkpoint catches the rewrite
        (folder / f"{ME}.reset.{int(now[0] + 10 * 365 * 86400)}").write_text("")
        _fresh(audit)
        ok, why = audit.verify()
        assert not ok and "future" in why                # and a reset from the future can't hide it
    finally:
        db.close()


def test_genuine_reset_still_works(tmp_path, folder):
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, Owners(), now)
    try:
        audit.witness.checkpoint(db, force=True)
        now[0] += 10
        audit.reset()
        _fresh(audit)
        assert audit.verify() == (True, None)
        assert audit.witness.resets()
    finally:
        db.close()


def test_reset_within_slack_is_not_flagged(tmp_path, folder):
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, Owners(), now)
    try:
        (folder / f"{ME}.reset.{int(now[0] + FUTURE_SLACK - 5)}").write_text("")
        _fresh(audit)
        assert audit.verify()[0]
    finally:
        db.close()


def test_resets_and_checkpoints_planted_by_others_are_ignored(tmp_path, folder):
    owners = Owners()
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, owners, now)
    try:
        owners.plant(folder, f"{ME}.reset.{int(now[0] + 99999999)}")   # would be "future"...
        owners.plant(folder, f"{ME}.log.2", "0" * 64 + " 1")           # ...or a false alarm
        _fresh(audit)
        assert audit.verify() == (True, None)                         # neither counts
        assert audit.witness.resets() == []
    finally:
        db.close()


def test_squatted_checkpoint_name_still_gets_a_checkpoint(tmp_path, folder):
    owners = Owners()
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, owners, now)
    try:
        last = db.conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
        owners.plant(folder, f"{ME}.log.{last}", "0" * 64 + " 1")
        assert audit.witness.checkpoint(db, force=True)
        ours = [n for n in os.listdir(folder) if n.startswith(f"{ME}.log.{last}.")]
        assert len(ours) == 1
        _rewrite_everything(db, tmp_path / "audit.head", last, "edited")
        _fresh(audit)
        assert not audit.verify()[0]                      # our checkpoint still catches the rewrite
    finally:
        db.close()


def test_other_file_kinds_are_ignored_by_the_witness(tmp_path, folder):
    now = [time.time()]
    db, audit = _logged(tmp_path, folder, Owners(), now)
    try:
        (folder / f"{ME}.marker.abc").write_text("")
        (folder / f"{ME}.junk.1").write_text("not a checkpoint")
        _fresh(audit)
        assert audit.verify() == (True, None)
    finally:
        db.close()


# -- elevated code doesn't write to other users' databases ---------------------------------------

def _snapshot(d):
    # The database itself. A read-only SQLite reader may create empty -wal/-shm side files for a
    # WAL database; those hold no data, so they are not compared.
    return {p.name: p.read_bytes() for p in sorted(d.iterdir()) if not p.name.endswith(("-wal", "-shm"))}


def test_uninstall_gate_leaves_unprotected_users_untouched(tmp_path):
    from gatekeeper.uninstall import UninstallGate
    guest = tmp_path / "guest"
    guest.mkdir()
    db = Database(guest / "gatekeeper.db")
    db.set_setting("theme", "dark")                 # set up the app, never chose a password
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    before = _snapshot(guest)
    gate = UninstallGate([guest, _user(tmp_path, "owner")])
    try:
        assert [u.owner for u in gate.users] and len(gate.users) == 1
    finally:
        gate.close()
    assert _snapshot(guest) == before


def test_folder_release_reads_only(tmp_path):
    from gatekeeper.folders import SETTING, release_everywhere
    target = tmp_path / "Private"
    target.mkdir()
    d = _user(tmp_path, "owner", **{SETTING: json.dumps([{"path": str(target), "locked": True}])})
    db = Database(d / "gatekeeper.db")
    db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()
    before = _snapshot(d)

    class Backend:
        unlocked = []

        def unlock(self, path):
            self.unlocked.append(path)
    backend = Backend()
    assert release_everywhere([d], backend) == 1 and backend.unlocked == [str(target)]
    assert _snapshot(d) == before


def test_folder_release_survives_junk_settings(tmp_path):
    from gatekeeper.folders import SETTING, release_everywhere
    d = _user(tmp_path, "owner", **{SETTING: "{not json"})
    assert release_everywhere([d], object()) == 0
    d2 = _user(tmp_path, "owner2", **{SETTING: json.dumps({"path": "x"})})  # an object, not a list
    assert release_everywhere([d2], object()) == 0


# -- an installed guard with missing data fails closed -------------------------------------------

def test_installed_guard_with_missing_data_locks_windows(tmp_path, folder, monkeypatch):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    from gatekeeper import winapi
    from gatekeeper.dashboard import Dashboard
    locked = []
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(winapi, "lock_workstation", lambda: locked.append(1) or True)

    class Runtime:
        running = False

        def start(self):
            pytest.fail("nothing to guard")

        def stop(self):
            pass
    ctx = open_context(False, tmp_path / "d", console=False)
    ctx.enrolment = Enrolment(folder, sid=ME, owner_fn=lambda p: ME)
    ctx.enrolment.mark()
    app = Dashboard(ctx, relaunch_args=["--service", "gui"], runtime=Runtime(), root=root)
    try:
        app.start()
        deadline = time.monotonic() + 3
        while not locked and time.monotonic() < deadline:
            root.update()
            time.sleep(0.05)
        assert locked == [1]
        assert dashdata.query_events(ctx.db, event="tamper_detected")
    finally:
        app.shutdown()
        root.destroy()
        ctx.db.close()


# -- the Windows SID helpers really work (they used to fail on every call) -----------------------

@pytest.mark.skipif(os.name != "nt", reason="Windows SIDs")
def test_current_sid_works_whatever_was_imported_first():
    import gatekeeper.crypto  # noqa: F401  declares LocalFree on the shared kernel32 first
    from gatekeeper.enrolment import current_sid
    sid = current_sid()
    assert sid.startswith("S-1-5-") and current_sid() == sid


@pytest.mark.skipif(os.name != "nt", reason="Windows SIDs")
def test_is_system_answers_without_failing(monkeypatch):
    from gatekeeper import enrolment
    assert watchdog.is_system() is False            # tests don't run as SYSTEM
    monkeypatch.setattr(enrolment, "current_sid", lambda: "S-1-5-18")
    assert watchdog.is_system() is True


@pytest.mark.skipif(os.name != "nt", reason="Windows file owners")
def test_real_markers_are_written_and_trusted(folder):
    from gatekeeper.enrolment import current_sid
    e = Enrolment(folder, owner_fn=file_owner_sid)   # the real SID and the real owner check
    assert e.mark() and e.enrolled()
    assert (folder / current_sid()).is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows file owners")
def test_real_owner_check_rejects_a_marker_for_another_sid(folder):
    (folder / OTHER).write_text("")                   # we created it, so we own it, not OTHER
    assert not Enrolment(folder, sid=OTHER, owner_fn=file_owner_sid).enrolled()


# -- unreadable databases fail closed (regressions from the read-only change) -------------------

def _corrupt(tmp_path, name):
    d = tmp_path / name
    d.mkdir()
    (d / "gatekeeper.db").write_bytes(b"not a database" * 200)
    return d


@pytest.fixture
def held(tmp_path):
    """A protected user's database held exclusively by another program (in use or deliberately locked)."""
    import sqlite3
    d = _user(tmp_path, "held")
    conn = sqlite3.connect(str(d / "gatekeeper.db"))
    conn.execute("PRAGMA locking_mode=EXCLUSIVE")
    conn.execute("BEGIN EXCLUSIVE")
    conn.execute("UPDATE settings SET value=value")
    yield d
    conn.rollback()
    conn.close()


def test_strict_read_tells_missing_from_unreadable(tmp_path):
    from gatekeeper.watchdog import read_settings
    bad = _corrupt(tmp_path, "bad")
    assert read_settings(tmp_path / "missing", ["password_hash"], strict=True) == {}
    assert read_settings(bad, ["password_hash"], strict=True) is None
    assert read_settings(bad, ["password_hash"]) == {}              # the old, lenient answer stays


def test_watchdog_treats_an_unreadable_database_as_protected(tmp_path):
    assert protected(_corrupt(tmp_path, "bad"))


def test_uninstall_refuses_when_a_database_is_corrupt(tmp_path, monkeypatch):
    from gatekeeper import uninstall
    owner = _user(tmp_path, "owner")
    bad = _corrupt(tmp_path, "bad")
    warned = []
    monkeypatch.setattr(uninstall, "data_dir", lambda: owner)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda _own: [owner, bad])
    asked = []
    assert not uninstall.confirm_uninstall(lambda u: asked.append(u.owner) or True, warn=warned.append)
    assert asked == []                                  # refused before any prompt
    assert warned and "could not be read" in warned[0]


def test_uninstall_refuses_when_a_database_is_held(tmp_path, held, monkeypatch):
    from gatekeeper import uninstall
    monkeypatch.setattr(uninstall, "data_dir", lambda: held)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda _own: [held])
    assert not uninstall.confirm_uninstall(lambda u: True)


def test_uninstall_still_skips_readable_unprotected_users(tmp_path, monkeypatch):
    from gatekeeper import uninstall
    guest = _user(tmp_path, "guest", password=False)
    monkeypatch.setattr(uninstall, "data_dir", lambda: guest)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda _own: [guest])
    assert uninstall.confirm_uninstall(lambda u: pytest.fail("nobody to ask"))


def test_uninstall_still_asks_every_protected_user(tmp_path, monkeypatch):
    from gatekeeper import uninstall
    a, b = _user(tmp_path, "a"), _user(tmp_path, "b")
    monkeypatch.setattr(uninstall, "data_dir", lambda: a)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda _own: [a, b])
    asked = []
    assert uninstall.confirm_uninstall(lambda u: asked.append(u) or u.verify(PASSWORD))
    assert len(asked) == 2


def test_folder_release_reports_unreadable_users(tmp_path):
    from gatekeeper.folders import release_everywhere
    bad = _corrupt(tmp_path, "bad")
    failed = []
    assert release_everywhere([bad], object(), failed=failed) == 0
    assert failed == [str(bad)]


def test_folder_release_falls_back_when_read_only_fails(tmp_path, monkeypatch):
    from gatekeeper import watchdog as wd
    from gatekeeper.folders import SETTING, release_everywhere
    target = tmp_path / "Private"
    target.mkdir()
    d = _user(tmp_path, "owner", **{SETTING: json.dumps([{"path": str(target), "locked": True}])})
    monkeypatch.setattr(wd, "read_settings", lambda *a, **k: None)   # read-only open refused

    class Backend:
        def __init__(self):
            self.unlocked = []

        def unlock(self, path):
            self.unlocked.append(path)
    backend, failed = Backend(), []
    assert release_everywhere([d], backend, failed=failed) == 1
    assert backend.unlocked == [str(target)] and failed == []


def test_release_folders_command_fails_loudly(tmp_path, monkeypatch, capsys):
    from gatekeeper import uninstall, winapi
    bad = _corrupt(tmp_path, "bad")
    monkeypatch.setattr(winapi, "is_admin", lambda: True)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda _own: [bad])
    monkeypatch.setattr("gatekeeper.config.data_dir", lambda *a, **k: bad)
    assert cli.release_folders_main() == 1
    assert str(bad) in capsys.readouterr().err


# -- Windows calls: declared prototypes, private DLL handles, no SYSTEM-environment fallback -----

def test_every_watchdog_call_has_a_prototype():
    if os.name != "nt":
        pytest.skip("Windows DLLs")
    api = watchdog._api()
    names = {"wts": ["WTSEnumerateSessionsW", "WTSFreeMemory", "WTSQueryUserToken", "WTSDisconnectSession"],
             "k32": ["CloseHandle", "ProcessIdToSessionId"],
             "adv": ["DuplicateTokenEx", "CreateProcessAsUserW"],
             "env": ["CreateEnvironmentBlock", "DestroyEnvironmentBlock"]}
    for dll, fns in names.items():
        for fn in fns:
            f = getattr(getattr(api, dll), fn)
            assert f.argtypes is not None, f"{dll}.{fn} has no argtypes"


@pytest.mark.skipif(os.name != "nt", reason="Windows DLLs")
def test_wrappers_survive_hostile_shared_prototypes(tmp_path):
    """Other code (or a library) declaring wrong prototypes on the shared ctypes.windll objects must
    not break Gatekeeper's own calls. Run in a fresh process so the sabotage can't leak into other tests."""
    import subprocess
    script = tmp_path / "sabotage.py"
    script.write_text(
        "import ctypes, os, sys\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "k = ctypes.windll.kernel32\n"
        "for name in ('CloseHandle', 'LocalFree', 'ProcessIdToSessionId', 'GetCurrentProcess'):\n"
        "    getattr(k, name).argtypes = [ctypes.c_char_p]\n"
        "    getattr(k, name).restype = ctypes.c_char\n"
        "a = ctypes.windll.advapi32\n"
        "for name in ('OpenProcessToken', 'GetTokenInformation', 'ConvertSidToStringSidW'):\n"
        "    getattr(a, name).argtypes = [ctypes.c_char_p]\n"
        "ctypes.windll.wtsapi32.WTSEnumerateSessionsW.argtypes = [ctypes.c_char_p]\n"
        "ctypes.windll.user32.GetAncestor.restype = ctypes.c_char\n"
        "from gatekeeper import crypto, watchdog\n"
        "from gatekeeper.enrolment import current_sid, file_owner_sid\n"
        "assert current_sid().startswith('S-1-5-')\n"
        "assert file_owner_sid(sys.argv[2]) is not None\n"
        "assert watchdog.session_of(os.getpid()) is not None\n"
        "assert watchdog.signed_in_sessions() == []\n"
        "assert crypto._dpapi(crypto._dpapi(b'x', True), False) == b'x'\n"
        "print('ok')\n", encoding="utf-8")
    probe = tmp_path / "owned"
    probe.write_text("")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = subprocess.run([sys.executable, str(script), root, str(probe)], capture_output=True, text=True,
                         timeout=60)
    assert out.returncode == 0 and out.stdout.strip() == "ok", out.stderr[-2000:]


class FakeWin:
    """Records the watchdog's launch calls; every call succeeds unless told otherwise."""

    def __init__(self, env_ok=True, create_ok=True):
        self.calls, self.closed = [], []
        self.env_ok, self.create_ok = env_ok, create_ok
        fake = self

        class Dll:
            def __getattr__(self, name):
                return getattr(fake, name)
        self.adv = self.env = self.k32 = self.wts = Dll()

    @staticmethod
    def _set(ref, value):
        ref._obj.value = value

    def DuplicateTokenEx(self, token, access, attrs, level, kind, out):
        self.calls.append("dup")
        self._set(out, 0x1111)
        return True

    def CreateEnvironmentBlock(self, out, token, inherit):
        self.calls.append("env")
        if self.env_ok:
            self._set(out, 0x2222)
        return self.env_ok

    def DestroyEnvironmentBlock(self, env):
        self.calls.append("destroy_env")
        return True

    def CreateProcessAsUserW(self, token, exe, cmdline, pa, ta, inherit, flags, env, cwd, si, pi):
        self.calls.append(("create", env))
        if self.create_ok:
            pi._obj.hProcess, pi._obj.hThread = 0x3333, 0x4444
        return self.create_ok

    def CloseHandle(self, handle):
        value = getattr(handle, "value", handle)
        self.closed.append(value)
        return True

    @staticmethod
    def error():
        return OSError("fake failure")


def _fake_token(_session):
    from ctypes import wintypes
    return wintypes.HANDLE(0x5555)


def test_launch_refuses_without_the_users_environment():
    win = FakeWin(env_ok=False)
    assert watchdog.launch(1, api=win, token_for=_fake_token) is False
    assert not any(isinstance(c, tuple) for c in win.calls), "must not start the guard with SYSTEM's environment"
    assert 0x1111 in win.closed and 0x5555 in win.closed       # duplicated and original token closed


def test_launch_passes_the_users_environment_and_closes_everything():
    win = FakeWin()
    assert watchdog.launch(1, api=win, token_for=_fake_token) is True
    assert ("create", ctypes_value(0x2222)) in [(c[0], ctypes_value(c[1])) for c in win.calls if isinstance(c, tuple)]
    assert {0x1111, 0x3333, 0x4444, 0x5555} <= set(win.closed)
    assert "destroy_env" in win.calls


def test_failed_create_still_frees_handles():
    win = FakeWin(create_ok=False)
    assert watchdog.launch(1, api=win, token_for=_fake_token) is False
    assert {0x1111, 0x5555} <= set(win.closed) and "destroy_env" in win.calls


def test_launch_without_a_token_does_nothing():
    win = FakeWin()
    assert watchdog.launch(1, api=win, token_for=lambda s: None) is False and win.calls == []


def ctypes_value(v):
    return getattr(v, "value", v)


def test_disconnect_never_targets_the_current_session():
    assert watchdog.disconnect_session(0xFFFFFFFF) is False
    assert watchdog.disconnect_session(None) is False


@pytest.mark.skipif(os.name != "nt", reason="Windows windows")
def test_top_level_window_lookup_returns_a_real_handle():
    tk = pytest.importorskip("tkinter")
    from gatekeeper import winapi
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    try:
        root.update()
        hwnd = winapi._top_level(root.winfo_id())
        assert isinstance(hwnd, int) and hwnd != 0
        winapi.make_click_through(root.winfo_id())   # must not raise with the declared prototypes
    finally:
        root.destroy()


@pytest.mark.skipif(os.name != "nt", reason="DPAPI")
def test_keys_written_by_older_versions_still_decrypt(tmp_path):
    """Older versions protected the key without CRYPTPROTECT_UI_FORBIDDEN; it must still unwrap."""
    import ctypes
    from ctypes import POINTER, byref, c_char, cast, create_string_buffer
    from gatekeeper import crypto
    data = b"old key material"
    crypt32 = ctypes.WinDLL("crypt32")
    buf = create_string_buffer(data, len(data))
    blob_in, blob_out = crypto._Blob(len(data), cast(buf, POINTER(c_char))), crypto._Blob()
    assert crypt32.CryptProtectData(byref(blob_in), None, None, None, None, 0, byref(blob_out))
    old = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    assert crypto._dpapi(old, protect=False) == data
