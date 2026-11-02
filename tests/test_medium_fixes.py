"""Medium-severity fixes: face unlock, USB, folder lock, uninstall and log checkpoints.
Everything Windows-specific is replaced by fakes, so these run on any system."""

import hashlib
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from gatekeeper import auth, cli, dashdata, faces, matcher, winapi
from gatekeeper.app import open_context
from gatekeeper.enrolment import Enrolment, setup_blocked, sync
from gatekeeper.folders import FolderLocker, release_everywhere, validate
from gatekeeper.logwitness import LogWitness
from gatekeeper.usb import UsbPolicy

PASSWORD = "correct horse battery"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path / "data", console=False)  # enforcing, with fake back ends below
    yield c
    c.db.close()


@pytest.fixture
def dev(tmp_path):
    c = open_context(True, tmp_path / "dev", console=False)
    yield c
    c.db.close()


# -- safety fixes for the previous change ---------------------------------------------------------

class BrokenEnrolment(Enrolment):
    @property
    def sid(self):
        raise TypeError("unexpected Windows API result")


def test_enrolment_errors_never_crash(ctx, tmp_path):
    folder = tmp_path / "enrolled"
    folder.mkdir()
    broken = BrokenEnrolment(folder)
    assert broken.mark() is False and broken.enrolled() is False
    auth.set_password(ctx.db, PASSWORD)
    sync(ctx.db, broken)                       # must not raise at startup
    assert setup_blocked(ctx.db, broken) is False


def test_session_locked_is_false_off_windows():
    if sys.platform != "win32":
        assert winapi.session_locked() is False


# -- #5 models are built from the bytes that were checked ------------------------------------------

def test_model_bytes_are_hash_checked(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_MODELS", str(tmp_path))
    good = b"model bytes"
    (tmp_path / "scrfd_500m.onnx").write_bytes(good)
    monkeypatch.setitem(faces.MODEL_HASHES, "scrfd_500m.onnx", hashlib.sha256(good).hexdigest())
    assert faces.verified_model_bytes("scrfd_500m.onnx") == good
    (tmp_path / "scrfd_500m.onnx").write_bytes(b"swapped")
    with pytest.raises(faces.ModelError):
        faces.verified_model_bytes("scrfd_500m.onnx")


def test_session_loads_from_verified_bytes(monkeypatch):
    seen = {}

    class FakeOrt:
        class SessionOptions:
            pass

        @staticmethod
        def InferenceSession(model, options, providers):
            seen["model"] = model
            return "session"
    monkeypatch.setitem(sys.modules, "onnxruntime", FakeOrt)
    monkeypatch.setattr(faces, "verified_model_bytes", lambda name: b"checked bytes")
    assert faces._session("arcface_mbf.onnx") == "session"
    assert seen["model"] == b"checked bytes"  # never a path that could be swapped after the check


def test_installed_build_ignores_models_env(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_MODELS", str(tmp_path / "planted"))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "bundle"), raising=False)
    assert faces.models_dir() == tmp_path / "bundle" / "models"


# -- #6 face attempts are limited -----------------------------------------------------------------

def test_face_attempts_pause_after_failures(ctx):
    auth.set_password(ctx.db, PASSWORD)
    for _ in range(auth.FACE_FREE_FAILURES - 1):
        auth.face_failed(ctx.db, ctx.audit)
    assert auth.face_locked_remaining(ctx.db) == 0
    auth.face_failed(ctx.db, ctx.audit)
    assert auth.face_locked_remaining(ctx.db) > 0
    assert dashdata.query_events(ctx.db, event="face_lockout")
    assert auth.check_password(ctx.db, PASSWORD)  # the owner's password lifts the pause
    assert auth.face_locked_remaining(ctx.db) == 0


def _face_ready(monkeypatch):
    monkeypatch.setattr(matcher, "face_unlock_enabled", lambda db: True)
    monkeypatch.setattr(matcher, "enrolment_current", lambda db: True)
    monkeypatch.setattr("gatekeeper.face_store.FaceStore", lambda *a: pytest.fail("must not load face data"))


def test_paused_face_unlock_is_not_offered(ctx, monkeypatch):
    _face_ready(monkeypatch)
    monkeypatch.setattr(matcher, "software_cameras", lambda: [])
    for _ in range(auth.FACE_FREE_FAILURES):
        auth.face_failed(ctx.db)
    assert matcher.build_face_unlock(ctx, lambda: None) is None


# -- #7 software cameras switch face unlock off ---------------------------------------------------

def test_software_camera_blocks_face_unlock(ctx, monkeypatch):
    _face_ready(monkeypatch)
    monkeypatch.setattr(matcher, "software_cameras", lambda: ["OBS Virtual Camera"])
    assert matcher.build_face_unlock(ctx, lambda: None) is None
    assert dashdata.query_events(ctx.db, event="face_virtual_camera")
    assert dashdata.blocking_cameras(ctx.db) == ["OBS Virtual Camera"]
    dashdata.allow_cameras(ctx, ["OBS Virtual Camera"])  # the owner says it's their real camera
    assert dashdata.blocking_cameras(ctx.db) == []


def test_virtual_camera_filter():
    assert matcher.virtual_cameras(found=["A", "B"]) == ["A", "B"]
    assert matcher.software_cameras() == [] or sys.platform == "win32"


# -- #8 strictness floor --------------------------------------------------------------------------

def test_threshold_floor(ctx):
    ctx.db.set_setting("face_threshold", 0.25)  # saved by an older version
    assert matcher.get_threshold(ctx.db) == matcher.WEAK_THRESHOLD
    with pytest.raises(ValueError):
        dashdata.set_face_options(ctx, True, 0.25, 10)


# -- #9 #10 #11 USB ---------------------------------------------------------------------------------

class FakeRegistry:
    def __init__(self, start=3):
        self.start = start

    def get_start(self):
        return self.start

    def set_start(self, value):
        self.start = value


class FakeExtras:
    def __init__(self):
        self.on = False

    def blocked(self):
        return self.on

    def set(self, block):
        self.on = block


class FakeScheduler:
    def __init__(self, ok=True):
        self.ok, self.scheduled, self.cancelled = ok, [], 0

    def schedule(self, when):
        self.scheduled.append(when)
        return self.ok

    def cancel(self):
        self.cancelled += 1
        return True


def _usb(ctx, now, scheduler=None):
    reg, extras = FakeRegistry(), FakeExtras()
    policy = UsbPolicy(ctx, reg, extras=extras, scheduler=scheduler or FakeScheduler(), clock=lambda: now[0])
    return policy, reg, extras


def test_block_covers_uasp_and_phones(ctx):
    now = [1000.0]
    policy, reg, extras = _usb(ctx, now)
    policy.block()
    assert reg.start == 4 and extras.on and policy.fully_blocked()
    extras.on = False                     # someone re-enabled UASP / phones
    assert policy.alert()
    assert policy.enforce() and extras.on
    policy.allow()
    assert reg.start == 3 and not extras.on


def test_temporary_allow_reblocks(ctx):
    now = [1000.0]
    scheduler = FakeScheduler()
    policy, reg, extras = _usb(ctx, now, scheduler)
    with pytest.raises(ValueError):
        policy.allow_temporarily(10)      # nothing blocked yet
    policy.block()
    with pytest.raises(ValueError):
        policy.allow_temporarily(0)
    assert policy.allow_temporarily("15") == 15
    assert reg.start == 3 and not extras.on
    assert scheduler.scheduled == [1000.0 + 15 * 60]  # SYSTEM task as a backstop
    now[0] += 60
    assert not policy.enforce() and reg.start == 3     # still inside the window
    assert policy.alert() == ""
    now[0] += 15 * 60
    assert policy.enforce() and reg.start == 4 and extras.on
    assert scheduler.cancelled == 1 and policy.temporary_remaining() == 0
    assert dashdata.query_events(ctx.db, event="usb_temporary_allow_ended")


def test_task_already_reblocked(ctx):
    now = [1000.0]
    policy, reg, extras = _usb(ctx, now)
    policy.block()
    policy.allow_temporarily(5)
    now[0] += 600
    reg.start, extras.on = 4, True        # the scheduled task ran while Gatekeeper was closed
    assert not policy.enforce()
    assert float(ctx.db.get_setting("usb_allow_until")) == 0


def test_reblock_task_failure_is_logged(ctx):
    now = [1000.0]
    policy, _reg, _extras = _usb(ctx, now, FakeScheduler(ok=False))
    policy.block()
    policy.allow_temporarily(5)
    assert dashdata.query_events(ctx.db, event="usb_reblock_task_failed")


def test_temporary_allow_dev_mode(dev):
    now = [1000.0]
    reg = FakeRegistry()
    policy = UsbPolicy(dev, reg, extras=FakeExtras(), scheduler=FakeScheduler(), clock=lambda: now[0])
    policy.block()
    policy.allow_temporarily(5)
    assert reg.start == 3                 # dev mode never touches the registry
    assert policy.temporary_remaining() == 300


# -- #12 folder lock ----------------------------------------------------------------------------------

class FakeBackend:
    def __init__(self):
        self.locked, self.calls = set(), []

    def lock(self, path):
        self.calls.append(("lock", path))
        self.locked.add(path)

    def unlock(self, path):
        self.calls.append(("unlock", path))
        self.locked.discard(path)

    def is_locked(self, path):
        return path in self.locked


@pytest.fixture
def private(tmp_path):
    d = tmp_path / "work" / "Private"
    d.mkdir(parents=True)
    return d


def test_folder_validation(ctx, tmp_path, private):
    assert validate(private, ctx.directory)[1] == ""
    assert "doesn't exist" in validate(tmp_path / "nope")[1]
    assert validate(ctx.directory, ctx.directory)[1]            # Gatekeeper's own data
    assert validate(tmp_path, ctx.directory)[1]                 # contains Gatekeeper's data
    assert validate("/" if sys.platform != "win32" else "C:\\")[1]  # a whole drive
    assert validate("")[1]


def test_lock_unlock_remove(ctx, private):
    backend = FakeBackend()
    folders = FolderLocker(ctx, backend)
    path = folders.add(private)
    assert backend.is_locked(path) and folders.status() == [(path, "locked")]
    with pytest.raises(ValueError):
        folders.add(private)                                    # already in the list
    inner = private / "inner"
    inner.mkdir()
    with pytest.raises(ValueError):
        folders.add(inner)                                      # inside a locked folder
    folders.set_locked(path, False)
    assert not backend.is_locked(path) and folders.status() == [(path, "unlocked")]
    assert folders.relock_all("Windows locked") == 1 and backend.is_locked(path)
    folders.remove(path)
    assert not backend.is_locked(path) and folders.entries() == []


def test_removed_lock_is_put_back(ctx, private):
    backend = FakeBackend()
    folders = FolderLocker(ctx, backend)
    path = folders.add(private)
    backend.locked.clear()                                      # someone edited the permissions
    assert folders.enforce() == 1 and backend.is_locked(path)
    assert dashdata.query_events(ctx.db, event="folder_lock_restored")
    folders.set_locked(path, False)
    backend.locked.clear()
    assert folders.enforce() == 0                               # unlocked on purpose: left alone


def test_folders_dev_mode_touches_nothing(dev, private):
    backend = FakeBackend()
    folders = FolderLocker(dev, backend)
    folders.add(private)
    assert backend.calls == []


def test_uninstaller_releases_everyones_folders(tmp_path, private):
    c = open_context(False, tmp_path / "u1", console=False)
    backend = FakeBackend()
    FolderLocker(c, backend).add(private)
    c.db.close()
    assert release_everywhere([tmp_path / "u1"], backend) == 1
    assert not backend.locked


def test_release_folders_needs_admin(monkeypatch, capsys):
    monkeypatch.setattr(winapi, "is_admin", lambda: False)
    assert cli.main(["release-folders"]) == 1
    assert "Administrator" in capsys.readouterr().out


def test_runtime_relock_includes_folders(ctx):
    from gatekeeper.runtime import GuardRuntime

    class Guard:
        reasons = []

        def relock(self, reason):
            self.reasons.append(reason)

    class Folders:
        reasons = []

        def relock_all(self, reason):
            self.reasons.append(reason)
    runtime = GuardRuntime(ctx, root=None)
    runtime.guard, runtime.folders = Guard(), Folders()
    runtime.relock("Windows locked")
    runtime._folder_job.join(timeout=5)
    assert Guard.reasons == ["Windows locked"] and Folders.reasons == ["Windows locked"]


# -- #14 log checkpoints ------------------------------------------------------------------------------

@pytest.fixture
def witnessed(tmp_path):
    folder = tmp_path / "enrolled"
    folder.mkdir()
    c = open_context(False, tmp_path / "w", console=False)
    now = [time.time()]
    c.audit.witness = LogWitness(Enrolment(folder, sid="S-1-5-21-w"), clock=lambda: now[0])
    yield c, now
    c.db.close()


def _rewrite(ctx, entry_id, detail):
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("UPDATE audit_log SET detail=?, hash=? WHERE id=?", (detail, "f" * 64, entry_id))


def test_checkpoint_catches_rewrite(witnessed):
    c, now = witnessed
    c.audit.record("unlocked", "chrome.exe")
    assert c.audit.witness.checkpoint(c.db)
    assert not c.audit.witness.checkpoint(c.db)       # at most hourly
    assert c.audit.verify() == (True, None)
    last = c.db.conn.execute("SELECT MAX(id) FROM audit_log").fetchone()[0]
    _rewrite(c, last, "nothing happened")
    c.audit.witness._cache = None
    ok, where = c.audit.verify()
    assert not ok


def test_checkpoint_survives_a_recomputed_chain(witnessed):
    """The attack the checkpoints exist for: rewrite the log AND recompute every hash and the seal."""
    from gatekeeper.audit import GENESIS, _digest
    c, now = witnessed
    c.audit.record("denied", "chrome.exe")
    c.audit.witness.checkpoint(c.db)
    with c.db.lock, c.db.conn:
        rows = c.db.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        prev = GENESIS
        for r in rows:
            detail = "harmless" if r["event"] == "denied" else r["detail"]
            digest = _digest(prev, r["ts"], r["event"], detail)
            c.db.conn.execute("UPDATE audit_log SET detail=?, prev_hash=?, hash=? WHERE id=?",
                              (detail, prev, digest, r["id"]))
            prev = digest
    c.audit.seal_path.write_text(f"{rows[-1]['id']} {prev}", encoding="ascii")
    c.audit._verified = None
    c.audit.witness._cache = None
    ok, where = c.audit.verify()
    assert not ok and "rewritten" in str(where)


def test_checkpoint_catches_deletion_but_allows_reset_and_retention(witnessed):
    c, now = witnessed
    c.audit.record("denied", "chrome.exe")
    c.audit.witness.checkpoint(c.db)
    with c.db.lock, c.db.conn:
        c.db.conn.execute("DELETE FROM audit_log")
    c.audit.seal_path.unlink()
    c.audit._verified = None
    c.audit.witness._cache = None
    assert "deleted" in str(c.audit.witness.verify(c.db)[1])
    now[0] += 200 * 86400                              # long past the 90-day retention: pruning is normal
    c.audit.witness._cache = None
    assert c.audit.witness.verify(c.db)[0]
    now[0] -= 200 * 86400 - 60                         # back to "a minute later"
    c.audit.reset()                                    # the owner's own reset: permanent and visible
    c.audit.witness._cache = None
    assert c.audit.verify() == (True, None)
    assert len(c.audit.witness.resets()) == 1


def test_witness_inactive_without_folder(ctx, tmp_path):
    w = LogWitness(Enrolment(tmp_path / "missing", sid="S-1"))
    assert not w.active and not w.checkpoint(ctx.db) and w.verify(ctx.db) == (True, "")
