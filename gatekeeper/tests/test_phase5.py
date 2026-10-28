import csv
import subprocess
import time

import psutil
import pytest

from gatekeeper import auth
from gatekeeper.app import open_context
from gatekeeper.audit import TAIL
from gatekeeper.guard import Guard, release_suspended


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path, console=False)
    yield c
    c.db.close()


# -- brute-force protection ------------------------------------------------------------
def test_lockout_after_five_failures_blocks_even_correct_password(ctx):
    auth.set_password(ctx.db, "correct horse")
    now = [1000.0]
    clock = lambda: now[0]
    for _ in range(4):
        assert not auth.check_password(ctx.db, "bad", ctx.audit, clock)
    assert auth.lockout_remaining(ctx.db, clock) == 0
    assert not auth.check_password(ctx.db, "bad", ctx.audit, clock)  # 5th failure engages lock
    assert auth.lockout_remaining(ctx.db, clock) == 30
    assert not auth.check_password(ctx.db, "correct horse", ctx.audit, clock)  # locked: even right pw refused
    now[0] += 31
    assert auth.check_password(ctx.db, "correct horse", ctx.audit, clock)
    assert ctx.db.get_setting("fail_count") == "0"


def test_lockout_backoff_doubles_and_caps(ctx):
    auth.set_password(ctx.db, "correct horse")
    now = [0.0]
    clock = lambda: now[0]
    waits = []
    for _ in range(12):
        auth.check_password(ctx.db, "bad", None, clock)
        waits.append(auth.lockout_remaining(ctx.db, clock))
        now[0] += auth.lockout_remaining(ctx.db, clock) + 1
    assert waits[4:7] == [30, 60, 120] and max(waits) == 900


def test_lockout_persists_across_restart(tmp_path):
    c = open_context(False, tmp_path, console=False)
    auth.set_password(c.db, "correct horse")
    for _ in range(5):
        auth.check_password(c.db, "bad")
    c.db.close()
    c2 = open_context(False, tmp_path, console=False)
    assert auth.lockout_remaining(c2.db) > 0
    c2.db.close()


# -- audit chain, seal, retention ------------------------------------------------------
def test_truncating_the_tail_is_detected_by_seal(ctx):
    for i in range(5):
        ctx.audit.record("e", str(i))
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("DELETE FROM audit_log WHERE id > 3")
    assert ctx.audit.verify() == (False, TAIL)


def test_seal_older_than_db_is_not_a_false_alarm(ctx):
    ctx.audit.record("a")
    seal = ctx.audit.seal_path.read_text()
    ctx.audit.record("b")
    ctx.audit.seal_path.write_text(seal)  # simulates a crash before the seal update
    assert ctx.audit.verify() == (True, None)


def test_prune_then_verify_with_real_timestamps(ctx, monkeypatch):
    import gatekeeper.audit as audit_mod
    real = audit_mod.datetime

    class Old(real):
        @classmethod
        def now(cls, tz=None):
            return real(2000, 1, 1, tzinfo=tz)

    monkeypatch.setattr(audit_mod, "datetime", Old)
    for i in range(3):
        ctx.audit.record("old", str(i))
    monkeypatch.setattr(audit_mod, "datetime", real)
    for i in range(3):
        ctx.audit.record("new", str(i))
    assert ctx.audit.prune(30) == 3
    assert ctx.audit.verify() == (True, None)
    events = [r["event"] for r in ctx.db.conn.execute("SELECT event FROM audit_log")]
    assert events[:3] == ["new"] * 3 and events[-1] == "log_pruned"


def test_csv_export_neutralises_formulas(ctx, tmp_path):
    ctx.audit.record("blocked", '=HYPERLINK("http://evil","x")')
    out = tmp_path / "log.csv"
    assert ctx.audit.export_csv(out) == 1
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0][:3] == ["id", "timestamp_utc", "event"]
    assert rows[1][3].startswith("'=")


def test_reset_starts_clean_valid_chain(ctx):
    ctx.audit.record("a")
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("UPDATE audit_log SET detail='x'")
    assert ctx.audit.verify()[0] is False
    ctx.audit.reset()
    assert ctx.audit.verify() == (True, None)


# -- recovery --------------------------------------------------------------------------
def test_release_resumes_frozen_locked_processes(ctx):
    ctx.db.add_app("ping.exe")
    victim = subprocess.Popen(["ping.exe", "-t", "127.0.0.1"], stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    guard = Guard(ctx, lambda n: None)
    try:
        guard.scan()
        assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED
        guard._pending.clear()  # simulate the guard having been force-killed
        assert release_suspended(ctx) == 1
        assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
    finally:
        victim.kill()


def test_unclean_shutdown_is_logged_on_next_start(ctx):
    from gatekeeper.app import startup_checks
    ctx.audit.record("guard_start", "enforcing")
    startup_checks(ctx, root=None)
    events = [r["event"] for r in ctx.db.conn.execute("SELECT event FROM audit_log")]
    assert "unclean_shutdown" in events
    ctx.audit.record("guard_stop")
    n = events.count("unclean_shutdown")
    startup_checks(ctx, root=None)
    events = [r["event"] for r in ctx.db.conn.execute("SELECT event FROM audit_log")]
    assert events.count("unclean_shutdown") == n
