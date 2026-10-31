"""Schedules, per-app stats, presets, checklist, theme, grace window and the new dashboard bits."""

import gc
import tkinter as tk
from datetime import date, datetime

import pytest

from gatekeeper import auth, dashdata, schedule
from gatekeeper.app import open_context
from gatekeeper.dashboard import Dashboard

PASSWORD = "correct horse battery"


@pytest.fixture
def ctx(tmp_path):
    c = open_context(True, tmp_path, console=False)
    yield c
    c.db.close()


# -- schedule (no display needed) ------------------------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("", None), ("09:00-17:00", (540, 1020)), (" 9:05 - 17:30 ", (545, 1050)), ("22:00-06:00", (1320, 360)),
])
def test_schedule_parse(text, expected):
    assert schedule.parse(text) == expected


@pytest.mark.parametrize("text", ["banana", "25:00-26:00", "09:00-09:00", "09:60-10:00", "9-10"])
def test_schedule_rejects_bad_input(text):
    with pytest.raises(ValueError):
        schedule.parse(text)


def test_schedule_window_and_overnight():
    at = lambda h, m=0: datetime(2026, 1, 5, h, m)  # noqa: E731
    assert schedule.is_active("", at(3))                          # no schedule = always
    assert schedule.is_active("09:00-17:00", at(9)) and not schedule.is_active("09:00-17:00", at(17))
    assert schedule.is_active("22:00-06:00", at(23)) and schedule.is_active("22:00-06:00", at(5, 59))
    assert not schedule.is_active("22:00-06:00", at(12))
    assert schedule.is_active("garbage", at(12))                  # unparseable fails safe: locked


def test_guard_only_enforces_active_schedules(ctx):
    ctx.db.add_app("a.exe")
    ctx.db.add_app("b.exe")
    schedule.set_window(ctx.db, "b.exe", "09:00-17:00")
    assert schedule.locked_now(ctx.db, datetime(2026, 1, 5, 12)) == {"a.exe", "b.exe"}
    assert schedule.locked_now(ctx.db, datetime(2026, 1, 5, 20)) == {"a.exe"}


def test_set_app_schedule_validates_and_audits(ctx):
    ctx.db.add_app("a.exe")
    assert dashdata.set_app_schedule(ctx, "a.exe", "9:00", "17:00", False) == "09:00-17:00"
    with pytest.raises(ValueError):
        dashdata.set_app_schedule(ctx, "a.exe", "x", "y", False)
    assert schedule.get(ctx.db, "a.exe") == "09:00-17:00"          # bad input left it unchanged
    assert dashdata.set_app_schedule(ctx, "a.exe", "", "", True) == ""
    assert dashdata.query_events(ctx.db, event="app_schedule_set")


# -- stats, presets, checklist ----------------------------------------------------------------------

def test_app_stats_and_overview(ctx):
    ctx.db.add_app("chrome.exe")
    ctx.audit.record("blocked", "chrome.exe pid=10")
    ctx.audit.record("blocked", "chrome.exe pid=11")
    ctx.audit.record("denied", "chrome.exe (1 process(es))")
    ctx.audit.record("blocked", "steam.exe pid=3")
    stats = dashdata.app_stats(ctx.db)
    assert stats["chrome.exe"]["blocked"] == 2 and stats["chrome.exe"]["denied"] == 1
    assert dashdata.top_apps(ctx.db) == [("chrome.exe", 2), ("steam.exe", 1)]
    name, _added, sched, last, denied = dashdata.locked_apps_overview(ctx.db)[0]
    assert (name, sched, denied) == ("chrome.exe", "Always", 1) and last != "never"


def test_problems_count_matches_the_problems_filter(ctx):
    ctx.audit.record("bad_password", "dashboard")
    ctx.audit.record("denied", "x.exe")
    ctx.audit.record("lockout", "5 failures")
    ctx.audit.record("unlocked", "x.exe")
    assert dashdata.problems_since(ctx.db, 24) == 3
    assert len(dashdata.query_events(ctx.db, severity="bad")) == 3


def test_presets_skip_protected_and_existing(ctx):
    first = dashdata.add_preset(ctx, "Browsers")
    assert "chrome.exe" in first and not dashdata.add_preset(ctx, "Browsers")
    assert dashdata.add_preset(ctx, "no such preset") == []


def test_checklist_progress_and_dismiss(ctx):
    done = lambda: [d for _l, d, _p in dashdata.checklist(ctx)]  # noqa: E731
    assert done() == [False, False, False, False]
    auth.set_password(ctx.db, PASSWORD)
    ctx.db.add_app("a.exe")
    ctx.db.set_setting("usb_choice_made", "1")
    assert done() == [True, True, True, False]
    assert not dashdata.checklist_dismissed(ctx.db)
    dashdata.dismiss_checklist(ctx.db)
    assert dashdata.checklist_dismissed(ctx.db)


def test_theme_and_grace_settings(ctx):
    assert dashdata.get_theme(ctx.db) == "light" and not dashdata.confirm_grace(ctx.db)
    dashdata.set_theme(ctx, "dark")
    dashdata.set_confirm_grace(ctx, True)
    assert dashdata.get_theme(ctx.db) == "dark" and dashdata.confirm_grace(ctx.db)
    dashdata.set_theme(ctx, "nonsense")
    assert dashdata.get_theme(ctx.db) == "light"


def test_query_events_by_day(ctx):
    ctx.audit.record("denied", "x.exe")
    today = datetime.now().astimezone().date()
    assert len(dashdata.query_events(ctx.db, day=today)) == 1
    assert dashdata.query_events(ctx.db, day=date(2000, 1, 1)) == []


# -- dashboard (needs a display) -----------------------------------------------------------------------

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
    # Free Tk variables here, on the main thread: if the GC runs them later on a worker thread
    # (e.g. the face-unlock tests) Tcl blocks waiting for a main loop that is not running.
    gc.collect()


class FakeRuntime:
    running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def apply_idle_setting(self):
        pass


@pytest.fixture(autouse=True)
def quiet_dialogs(monkeypatch):
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(f"tkinter.messagebox.{name}", lambda *a, **k: None)
    monkeypatch.setattr("tkinter.messagebox.askyesno", lambda *a, **k: True)


def logged_in(ctx, root):
    auth.set_password(ctx.db, PASSWORD)
    app = Dashboard(ctx, root=root, runtime=FakeRuntime())
    app.start()
    app.login_var.set(PASSWORD)
    app.login_submit()
    root.update()
    assert app.authed
    return app


def test_failed_tile_and_click_through_to_log(ctx, root):
    ctx.audit.record("bad_password", "dashboard")
    ctx.audit.record("unlocked", "a.exe")
    app = logged_in(ctx, root)
    page = app.pages["dashboard"]
    page.refresh()
    assert page.tiles["fails"][0].get() == "1"
    app.open_log(severity="bad", range_label="Last 24 hours")
    log = app.pages["log"]
    assert app.current == "log" and log.severity == "bad"
    events = {log.tree.item(i, "values")[1] for i in log.tree.get_children()}
    assert events == {"Wrong password"}


def test_chart_modes_and_day_click(ctx, root):
    ctx.audit.record("blocked", "chrome.exe pid=1")
    app = logged_in(ctx, root)
    page = app.pages["dashboard"]
    for mode in ("Unlocked vs denied", "Blocked starts", "Most-attempted apps"):
        page.mode_var.set(mode)
        page._mode_changed()
        root.update()
    page.mode_var.set("Blocked starts")
    page._mode_changed()
    root.update()
    page.chart.update_idletasks()
    left, slot, count = page.chart.geometry_info
    class Click:  # last day column
        x = left + slot * (count - 0.5)
    page._chart_click(Click)
    assert app.current == "log" and app.pages["log"].day == datetime.now().astimezone().date()
    assert len(app.pages["log"].tree.get_children()) >= 1
    app.pages["log"].set_day(None)
    assert app.pages["log"].day is None


def test_checklist_card_and_dismiss(ctx, root):
    app = logged_in(ctx, root)
    page = app.pages["dashboard"]
    assert page.check_holder.winfo_children()  # fresh install: steps still to do
    page._dismiss_checklist()
    assert not page.check_holder.winfo_children()


def test_apps_schedule_and_preset(ctx, root):
    app = logged_in(ctx, root)
    app.show_page("apps")
    page = app.pages["apps"]
    page.add_preset("Browsers")
    assert "chrome.exe" in ctx.db.list_apps()
    chrome = next(i for i in page.tree.get_children() if page.tree.item(i, "values")[0] == "chrome.exe")
    page.tree.selection_set(chrome)
    page.schedule_selected()
    always, start, end = page.schedule_vars
    always.set(False)
    start.set("22:00")
    end.set("06:00")
    page.save_schedule()
    assert schedule.get(ctx.db, "chrome.exe") == "22:00-06:00"
    shown = [page.tree.item(i, "values") for i in page.tree.get_children()]
    assert any(v[0] == "chrome.exe" and v[2] == "22:00-06:00" for v in shown)
    chrome = next(i for i in page.tree.get_children() if page.tree.item(i, "values")[0] == "chrome.exe")
    page.tree.selection_set(chrome)
    app.confirm_password = lambda *a, **k: True  # removing an app asks for the password
    page.remove_selected()
    assert schedule.get(ctx.db, "chrome.exe") == "" and "chrome.exe" not in ctx.db.list_apps()


def test_theme_switch_rebuilds_and_persists(ctx, root):
    from gatekeeper.gui_widgets import P
    app = logged_in(ctx, root)
    app.show_page("settings")
    page = app.pages["settings"]
    page.theme_var.set("Dark")
    page.save_behaviour()
    root.update()
    assert dashdata.get_theme(ctx.db) == "dark" and P["bg"] == "#0f172a" and app.current == "settings"
    app.apply_theme("light")
    assert P["bg"] == "#f3f4f6"


def test_confirm_grace_skips_second_prompt(ctx, root):
    app = logged_in(ctx, root)
    dashdata.set_confirm_grace(ctx, True)
    app._confirmed_until = __import__("time").monotonic() + 30
    assert app.confirm_password("do something")           # remembered: no dialog needed
    app._confirmed_until = 0.0


def test_lockout_message_shown_on_login_screen(ctx, root):
    auth.set_password(ctx.db, PASSWORD)
    ctx.db.set_setting("locked_until", __import__("time").time() + 30)
    app = Dashboard(ctx, root=root, runtime=FakeRuntime())
    app.start()
    root.update()
    labels = [w for w in app.stage.winfo_children()[0].winfo_children()[0].winfo_children()[0].winfo_children()
              if w.winfo_class() == "TLabel" and "Too many" in str(w.cget("text"))]
    assert labels, "lockout message should appear without pressing the button"


def test_banner_appears_when_chain_is_broken(ctx, root):
    app = logged_in(ctx, root)
    assert not app.banner.winfo_ismapped()
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("UPDATE audit_log SET detail='tampered' WHERE id=1")
    app._update_banner()
    root.update()
    assert "tampering" in app.banner.cget("text") and app.banner.winfo_ismapped()


# -- Face ID style animation ---------------------------------------------------------------------------

def test_brackets_close_into_a_circle():
    from gatekeeper import face_anim as fa
    import math
    open_corners = fa.brackets(50, 13, 0.44)
    assert len(open_corners) == 4
    # coverage < 1 leaves gaps: the end of one bracket is not the start of the next
    assert open_corners[0][-1] != open_corners[1][0]
    closed = fa.brackets(50, 50, 1.0)
    for line in closed:
        assert all(abs(math.hypot(x, y) - 50) < 0.6 for x, y in line)   # every point sits on the circle
    assert math.dist(closed[0][-1], closed[1][0]) < 1.0                 # and neighbours now touch


def test_color_mix_and_partial_path():
    from gatekeeper import face_anim as fa
    assert fa.mix("#000000", "#ffffff", 0.5) == "#808080" and fa.mix("#102030", "#ffffff", 0) == "#102030"
    path = [(0, 0), (10, 0), (10, 10)]
    assert fa.partial(path, 0.5)[-1] == (10, 0) and fa.partial(path, 1.0)[-1] == (10, 10)
    assert fa.partial(path, 0.75)[-1] == (10, 5)


def test_animation_states_draw(root):
    from gatekeeper import face_anim as fa
    a = fa.FaceIDAnimation(root, size=160)
    colors = {}
    for state, t in ((fa.IDLE, 0), (fa.SCANNING, 0.5), (fa.SUCCESS, 0.1), (fa.SUCCESS, 1.0),
                     (fa.FAILURE, 0.1), (fa.UNAVAILABLE, 0)):
        a.state = state
        a.draw_at(t)
        colors[(state, t)] = {a.itemcget(i, "fill") for i in a.find_all()}
        assert a.find_all(), state
    assert fa.GREEN in colors[(fa.SUCCESS, 1.0)]                         # ends as a green circle + check
    assert not any(c == fa.GREEN for c in colors[(fa.IDLE, 0)])
    assert len(colors[(fa.SCANNING, 0.5)]) > len(colors[(fa.IDLE, 0)])    # the mesh lights up while scanning
    a.state = fa.SUCCESS
    assert a.animating(0.5) and not a.animating(5)
    a.set_state(fa.SCANNING)
    root.update()
    a.destroy()
    root.update()  # the pending frame callback must not fire on a destroyed widget


def test_prompt_shows_success_animation_before_unlocking(root):
    from gatekeeper import face_anim as fa
    from gatekeeper.ui import UnlockPrompt
    results = []

    class Face:
        state, best = "idle", 0.9
        def start(self): self.state = "matched"
        def cancel(self): pass

    prompt = UnlockPrompt(root, "x.exe", lambda pw: False, results.append, face=Face(), fullscreen=False)
    for _ in range(10):
        root.update()
        __import__("time").sleep(0.02)
    assert prompt.anim.state == fa.SUCCESS and results == []   # animation plays first...
    prompt.entry.insert(0, "x")
    prompt._submit()
    assert results == []                                        # ...and typing can't race it
    end = __import__("time").monotonic() + 2
    while not results and __import__("time").monotonic() < end:
        root.update()
        __import__("time").sleep(0.02)
    assert results == [True]


def test_fullscreen_overlay_blurs_screen_and_fades(root):
    import time
    from gatekeeper import winapi
    from gatekeeper.ui import UnlockPrompt
    results = []
    prompt = UnlockPrompt(root, "x.exe", lambda pw: pw == "ok", results.append)
    vx, vy, vw, vh = winapi.virtual_screen()
    root.update()
    assert prompt.win.winfo_width() == vw and prompt.win.winfo_height() == vh   # covers the whole desktop
    assert prompt._backdrop is not None                                        # blurred screenshot is shown
    alphas = []
    end = time.monotonic() + 0.6
    while time.monotonic() < end:
        root.update()
        alphas.append(float(prompt.win.attributes("-alpha")))
        time.sleep(0.01)
    assert alphas[0] < 0.6 and alphas[-1] == 1.0                                # faded in
    assert all(b >= a - 1e-9 for a, b in zip(alphas, alphas[1:]))               # monotonic: no flicker
    assert len({round(a, 2) for a in alphas}) > 8                               # many steps = smooth, not a jump
    prompt.entry.insert(0, "ok")
    prompt._submit()
    assert results == [True]                                                    # app resumes immediately
    fading = []
    end = time.monotonic() + 0.6
    while time.monotonic() < end and prompt.win.winfo_exists():
        root.update()
        try:
            fading.append(float(prompt.win.attributes("-alpha")))
        except tk.TclError:
            break
        time.sleep(0.01)
    assert len(fading) > 5 and fading[0] > fading[-1]                           # faded out, then was destroyed
    root.update()
    assert not prompt.win.winfo_exists()
