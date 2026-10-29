"""Tk-free logic behind the desktop dashboard."""

from datetime import datetime, timedelta, timezone

import pytest

from gatekeeper import auth, dashdata
from gatekeeper.app import open_context

PASSWORD = "correct horse battery"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(True, tmp_path, console=False)  # dev mode: nothing touches the real OS
    yield c
    c.db.close()


def _old_event(ctx, event, days_ago, detail=""):
    ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("INSERT INTO audit_log(ts,event,detail,prev_hash,hash) VALUES(?,?,?,?,?)",
                            (ts, event, detail, "x", "y"))


# -- app names -----------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("Notepad", "notepad.exe"), ("  chrome  ", "chrome.exe"), ('"Chrome.EXE"', "chrome.exe"),
    (r"C:\Program Files\Foo\Bar.EXE", "bar.exe"), ("a/b/c.exe", "c.exe"), ("   ", "")])
def test_normalize_exe(raw, expected):
    assert dashdata.normalize_exe(raw) == expected


def test_validate_app_refuses_system_and_empty():
    assert dashdata.validate_app("cmd")[0] == ""
    assert "protected" in dashdata.validate_app("explorer.exe")[1]
    assert "name" in dashdata.validate_app("  ")[1].lower()
    assert dashdata.validate_app("Spotify") == ("spotify.exe", "")


def test_locked_apps_detailed(ctx):
    ctx.db.add_app("zoom.exe")
    ctx.db.add_app("chrome.exe")
    names = [n for n, _ in dashdata.locked_apps_detailed(ctx.db)]
    assert names == ["chrome.exe", "zoom.exe"]


def test_running_apps_excludes_protected():
    names = dashdata.running_apps()
    assert all(n.endswith(".exe") for n in names)
    assert not set(names) & dashdata.PROTECTED_PROCESSES


# -- audit views -----------------------------------------------------------------------------------

def test_query_events_filters(ctx):
    _old_event(ctx, "denied", 10, "ancient")  # oldest row, so it has the lowest id like real history
    ctx.audit.record("blocked", "chrome.exe pid=1")
    ctx.audit.record("denied", "chrome.exe (1 process(es))")
    ctx.audit.record("unlocked", "notepad.exe (1 process(es))")
    assert len(dashdata.query_events(ctx.db)) == 4
    assert [r["event"] for r in dashdata.query_events(ctx.db, event="denied")] == ["denied", "denied"]
    assert [r["event"] for r in dashdata.query_events(ctx.db, text="NOTEPAD")] == ["unlocked"]
    recent = dashdata.query_events(ctx.db, event="denied", hours=24)
    assert [r["detail"] for r in recent] == ["chrome.exe (1 process(es))"]
    assert len(dashdata.query_events(ctx.db, limit=2)) == 2
    assert dashdata.query_events(ctx.db)[0]["event"] == "unlocked"  # newest first
    assert dashdata.count_events(ctx.db) == 4
    assert dashdata.event_types(ctx.db) == ["blocked", "denied", "unlocked"]


def test_text_search_treats_wildcards_literally(ctx):
    ctx.audit.record("blocked", "100% sure")
    ctx.audit.record("blocked", "other")
    assert len(dashdata.query_events(ctx.db, text="%")) == 1


def test_activity_by_day(ctx):
    ctx.audit.record("unlocked", "a")
    ctx.audit.record("unlocked", "b")
    ctx.audit.record("denied", "c")
    ctx.audit.record("guard_start")  # not counted
    _old_event(ctx, "denied", 2)
    _old_event(ctx, "unlocked", 30)  # outside the window
    days = dashdata.activity_by_day(ctx.db, 7)
    assert len(days) == 7
    assert days[0]["date"] < days[-1]["date"]
    assert (days[-1]["unlocked"], days[-1]["denied"]) == (2, 1)
    assert sum(d["denied"] for d in days) == 2
    assert sum(d["unlocked"] for d in days) == 2


def test_describe_and_severity():
    assert dashdata.describe("bad_password") == "Wrong password"
    assert dashdata.describe("some_new_event") == "Some new event"
    assert dashdata.severity("denied") == "bad"
    assert dashdata.severity("unlocked") == "good"
    assert dashdata.severity("blocked") == "warn"
    assert dashdata.severity("anything_else") == "info"


def test_local_time_formats_and_tolerates_junk():
    assert len(dashdata.local_time("2026-10-28T12:00:00+00:00")) == 19
    assert dashdata.local_time("not a time") == "not a time"


# -- status and summary ------------------------------------------------------------------------------

def test_summary(ctx):
    ctx.db.add_app("chrome.exe")
    ctx.audit.record("unlocked", "chrome.exe")
    s = dashdata.summary(ctx)
    assert s["apps"] == ["chrome.exe"] and s["dev"] is True
    assert s["chain_ok"] is True and s["face_samples"] == 0 and s["face_enabled"] is True
    assert s["last24"]["unlocked"] == 1 and s["last_event"]["event"] == "unlocked"
    assert s["usb_status"] in ("blocked", "allowed", "unknown")


# -- validated setters -----------------------------------------------------------------------------------

def test_set_idle_minutes(ctx):
    assert dashdata.set_idle_minutes(ctx, "15") == 15
    assert ctx.db.get_setting("idle_lock_minutes") == "15.0"
    for bad in ("-1", "abc", "5000", ""):
        with pytest.raises(ValueError):
            dashdata.set_idle_minutes(ctx, bad)
    assert ctx.db.get_setting("idle_lock_minutes") == "15.0"
    assert dashdata.query_events(ctx.db, event="idle_lock_set")


def test_set_retention_and_autolock(ctx):
    assert dashdata.set_retention_days(ctx, "30") == 30
    with pytest.raises(ValueError):
        dashdata.set_retention_days(ctx, "-5")
    assert dashdata.autolock_minutes(ctx.db) == dashdata.DEFAULT_AUTOLOCK
    dashdata.set_autolock_minutes(ctx, 0)
    assert dashdata.autolock_minutes(ctx.db) == 0
    with pytest.raises(ValueError):
        dashdata.set_autolock_minutes(ctx, 1000)


def test_set_face_options(ctx):
    assert dashdata.set_face_options(ctx, True, 0.5, 10) == ""
    assert dashdata.face_options(ctx.db) == (True, 0.5, 10.0)
    assert "false accepts" in dashdata.set_face_options(ctx, False, 0.3, 5)
    assert dashdata.face_options(ctx.db) == (False, 0.3, 5.0)
    with pytest.raises(ValueError):
        dashdata.set_face_options(ctx, True, 0.95, 5)
    with pytest.raises(ValueError):
        dashdata.set_face_options(ctx, True, 0.5, 99)
    assert dashdata.face_options(ctx.db) == (False, 0.3, 5.0)  # a rejected save changes nothing


# -- passwords ------------------------------------------------------------------------------------------------

def test_create_password(ctx):
    assert dashdata.create_password(ctx, "short", "short")[0] is False
    assert dashdata.create_password(ctx, PASSWORD, "different")[0] is False
    assert not auth.has_password(ctx.db)
    assert dashdata.create_password(ctx, PASSWORD, PASSWORD) == (True, "")
    assert auth.verify_password(ctx.db, PASSWORD)
    assert dashdata.create_password(ctx, "another one!", "another one!")[0] is False  # cannot overwrite


def test_change_password(ctx):
    auth.set_password(ctx.db, PASSWORD)
    assert dashdata.change_password(ctx, "wrong", "new password 1", "new password 1")[0] is False
    assert dashdata.change_password(ctx, PASSWORD, "new password 1", "mismatch!!")[0] is False
    assert dashdata.change_password(ctx, PASSWORD, "tiny", "tiny")[0] is False
    ok, message = dashdata.change_password(ctx, PASSWORD, "new password 1", "new password 1")
    assert ok and message == "Password changed."
    assert auth.verify_password(ctx.db, "new password 1") and not auth.verify_password(ctx.db, PASSWORD)
    assert dashdata.query_events(ctx.db, event="password_set")


def test_change_password_shares_the_lockout(ctx):
    auth.set_password(ctx.db, PASSWORD)
    for _ in range(auth.FREE_FAILURES):
        dashdata.change_password(ctx, "wrong", "x" * 10, "x" * 10)
    ok, message = dashdata.change_password(ctx, PASSWORD, "new password 1", "new password 1")
    assert not ok and "Try again" in message
    assert auth.verify_password(ctx.db, PASSWORD)  # unchanged while locked out


# -- one guard per data folder ------------------------------------------------------------------------------------

def test_single_instance(tmp_path):
    first, second = dashdata.SingleInstance(tmp_path), dashdata.SingleInstance(tmp_path)
    assert first.acquire()
    assert not second.acquire()
    first.release()
    assert second.acquire()
    second.release()
    second.release()  # releasing twice is harmless


def test_single_instance_waits_for_release(tmp_path):
    import threading
    first, second = dashdata.SingleInstance(tmp_path), dashdata.SingleInstance(tmp_path)
    assert first.acquire()
    threading.Timer(0.5, first.release).start()
    assert second.acquire(wait=5)
    second.release()
