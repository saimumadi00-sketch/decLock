"""Builds the whole dashboard and clicks through it. Skipped where there is no display
(on Linux run it under `xvfb-run`)."""

import tkinter as tk

import pytest

from gatekeeper import auth, dashdata
from gatekeeper.app import open_context
from gatekeeper.dashboard import Dashboard
from gatekeeper.gui_pages import PAGES
from gatekeeper.runtime import GuardRuntime

PASSWORD = "correct horse battery"


@pytest.fixture
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    yield r
    try:
        r.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def ctx(tmp_path):
    c = open_context(True, tmp_path, console=False)
    yield c
    c.db.close()


class FakeRuntime:
    """Stands in for the guard threads and camera so the UI can be exercised alone."""
    running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def engine(self):
        raise RuntimeError("no models in tests")

    def apply_idle_setting(self):
        self.idle_applied = True


@pytest.fixture(autouse=True)
def quiet_dialogs(monkeypatch):
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(f"tkinter.messagebox.{name}", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda *a, **k: True)


def make_app(ctx, root, runtime=None):
    return Dashboard(ctx, root=root, runtime=runtime or FakeRuntime())


def logged_in(ctx, root, runtime=None):
    auth.set_password(ctx.db, PASSWORD)
    app = make_app(ctx, root, runtime)
    app.start()
    app.login_var.set(PASSWORD)
    app.login_submit()
    root.update()
    assert app.authed
    return app


def test_first_run_setup_then_dashboard(ctx, root):
    app = make_app(ctx, root)
    app.start()
    first, second = app.setup_vars
    first.set("short")
    second.set("short")
    app.setup_submit()
    assert not app.authed and not auth.has_password(ctx.db)  # too short
    first.set(PASSWORD)
    second.set(PASSWORD)
    app.setup_submit()
    root.update()
    assert app.authed and auth.verify_password(ctx.db, PASSWORD)
    assert app.runtime.running  # protection starts once a password exists


def test_login_wrong_then_right(ctx, root):
    auth.set_password(ctx.db, PASSWORD)
    app = make_app(ctx, root)
    app.start()
    assert app.runtime.running and not app.authed
    app.login_var.set("wrong one")
    app.login_submit()
    assert not app.authed and dashdata.query_events(ctx.db, event="bad_password")
    app.login_var.set(PASSWORD)
    app.login_submit()
    assert app.authed and dashdata.query_events(ctx.db, event="dashboard_login")


def test_every_page_builds_and_refreshes(ctx, root):
    ctx.db.add_app("chrome.exe")
    ctx.audit.record("unlocked", "chrome.exe")
    app = logged_in(ctx, root)
    for key, _label, _cls in PAGES:
        app.show_page(key)
        root.update()
        assert app.current == key
    app.pages["dashboard"].refresh()
    assert app.pages["dashboard"].tiles["apps"][0].get() == "1"


def test_apps_page_add_and_remove(ctx, root):
    app = logged_in(ctx, root)
    app.show_page("apps")
    page = app.pages["apps"]
    page.name_var.set("Notepad")
    page.add_typed()
    assert ctx.db.list_apps() == ["notepad.exe"]
    assert len(page.tree.get_children()) == 1
    page.name_var.set("cmd")
    page.add_typed()
    assert ctx.db.list_apps() == ["notepad.exe"] and "protected" in page.msg.cget("text")
    page.tree.selection_set(page.tree.get_children()[0])
    page.remove_selected()
    assert ctx.db.list_apps() == []
    assert dashdata.query_events(ctx.db, event="app_removed")


def test_usb_and_idle_page(ctx, root):
    runtime = FakeRuntime()
    app = logged_in(ctx, root, runtime)
    app.show_page("usb")
    page = app.pages["usb"]
    page.idle_var.set("12")
    page.apply_idle()
    assert float(ctx.db.get_setting("idle_lock_minutes")) == 12 and runtime.idle_applied
    page.idle_var.set("banana")
    page.apply_idle()
    assert float(ctx.db.get_setting("idle_lock_minutes")) == 12  # rejected, unchanged
    page.set_usb(True)  # dev mode: simulated, no registry access
    assert ctx.db.get_setting("usb_block") == "1"
    assert dashdata.query_events(ctx.db, event="usb_blocked_dev")


def test_face_page_settings_and_missing_models(ctx, root):
    app = logged_in(ctx, root)
    app.show_page("face")
    page = app.pages["face"]
    page.enabled_var.set(False)
    page.thr_var.set(0.55)
    page.timeout_var.set(12)
    page.save()
    assert dashdata.face_options(ctx.db) == (False, 0.55, 12.0)
    page.start_enroll()
    assert page.session is None and "unavailable" in page.msg.cget("text")
    page.start_test()  # nothing enrolled
    assert page.session is None and "Enroll" in page.msg.cget("text")


def test_log_page_filters_and_exports(ctx, root, tmp_path, monkeypatch):
    ctx.audit.record("denied", "chrome.exe")
    ctx.audit.record("unlocked", "notepad.exe")
    app = logged_in(ctx, root)
    app.show_page("log")
    page = app.pages["log"]
    page.range_var.set("All time")
    page.refresh()
    assert len(page.tree.get_children()) >= 2
    page.search_var.set("notepad")
    page.refresh()
    assert len(page.tree.get_children()) == 1
    page.search_var.set("")
    page.type_var.set("Access denied")
    page.refresh()
    assert len(page.tree.get_children()) == 1
    out = tmp_path / "out.csv"
    monkeypatch.setattr("tkinter.filedialog.asksaveasfilename", lambda *a, **k: str(out))
    page.export()
    assert out.read_text(encoding="utf-8").startswith("id,timestamp_utc,event,detail,hash")


def test_settings_page(ctx, root):
    app = logged_in(ctx, root)
    app.show_page("settings")
    page = app.pages["settings"]
    page.cur.set(PASSWORD)
    page.new.set("a brand new password")
    page.rep.set("a brand new password")
    page.change_password()
    assert auth.verify_password(ctx.db, "a brand new password")
    page.autolock_var.set("9")
    page.retention_var.set("45")
    page.save_behaviour()
    assert dashdata.autolock_minutes(ctx.db) == 9 and ctx.db.get_setting("log_retention_days") == "45"
    page.retention_var.set("-3")
    page.save_behaviour()
    assert ctx.db.get_setting("log_retention_days") == "45"


def test_lock_ui_returns_to_login_and_close_minimizes(ctx, root):
    app = logged_in(ctx, root)
    app.lock_ui("test")
    assert not app.authed and app.nav == {} and app.pages == {}
    assert dashdata.query_events(ctx.db, event="dashboard_locked")
    app.login_var.set(PASSWORD)
    app.login_submit()
    assert app.authed
    app.on_close()  # locks and minimizes; protection is untouched
    assert not app.authed and app.runtime.running


def test_auto_lock_after_inactivity(ctx, root):
    app = logged_in(ctx, root)
    dashdata.set_autolock_minutes(ctx, 1)
    app.last_activity -= 120
    app._tick()
    assert not app.authed


def test_shutdown_stops_runtime(ctx, root):
    runtime = FakeRuntime()
    app = logged_in(ctx, root, runtime)
    app.show_page("face")
    app.shutdown()
    assert not runtime.running


# -- the real runtime, in dev mode ---------------------------------------------------------------------------------

def test_guard_runtime_lifecycle(ctx, root):
    root.withdraw()
    runtime = GuardRuntime(ctx, root)
    runtime.start()
    runtime.start()  # idempotent
    assert runtime.running
    ctx.db.set_setting("idle_lock_minutes", 5)
    runtime.apply_idle_setting()
    assert runtime.idle_locker is not None
    ctx.db.set_setting("idle_lock_minutes", 0)
    runtime.apply_idle_setting()
    assert runtime.idle_locker is None
    runtime.stop()
    runtime.stop()
    assert not runtime.running
    events = [r["event"] for r in dashdata.query_events(ctx.db, limit=50)]
    assert events.count("guard_start") == 1 and events.count("guard_stop") == 1
    runtime.start()  # pause/resume works
    runtime.stop()
    assert [r["event"] for r in dashdata.query_events(ctx.db, limit=50)].count("guard_start") == 2
