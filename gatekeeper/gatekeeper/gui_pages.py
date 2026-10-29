"""The dashboard pages. Each page talks to the same db/auth/audit objects as the CLI (through
dashdata), so settings changed here and on the command line always agree."""

import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import dashdata, winapi
from .config import MIN_PASSWORD_LEN
from .gui_widgets import (FONT, P, CameraSession, center, draw_bars, make_card, make_pill,
                          set_pill)
from .matcher import THRESHOLD_RANGE


class Page(ttk.Frame):
    title = ""
    auto_refresh = False

    def __init__(self, parent, app):
        super().__init__(parent, padding=(24, 16))
        self.app, self.ctx = app, app.ctx
        ttk.Label(self, text=self.title, style="H1.TLabel").pack(anchor="w", pady=(0, 14))
        self.build()

    def build(self) -> None:
        pass

    def refresh(self) -> None:
        pass

    def leave(self) -> None:
        pass


def make_tree(parent, columns, height=10):
    """Treeview with a scrollbar. `columns` = [(id, heading, width, stretch)]."""
    frame = ttk.Frame(parent, style="Card.TFrame")
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height,
                        selectmode="browse")
    for ident, heading, width, stretch in columns:
        tree.heading(ident, text=heading, anchor="w")
        tree.column(ident, width=width, stretch=stretch, anchor="w")
    bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=bar.set)
    tree.pack(side="left", fill="both", expand=True)
    bar.pack(side="right", fill="y")
    tree.tag_configure("good", foreground=P["good"])
    tree.tag_configure("bad", foreground=P["bad"])
    tree.tag_configure("warn", foreground=P["warn"])
    return frame, tree


def fill_events(tree, rows) -> None:
    tree.delete(*tree.get_children())
    for r in rows:
        tree.insert("", "end", values=(dashdata.local_time(r["ts"]), dashdata.describe(r["event"]), r["detail"]),
                    tags=(dashdata.severity(r["event"]),))


# --------------------------------------------------------------------------------------------
class DashboardPage(Page):
    title = "Dashboard"
    auto_refresh = True

    def build(self) -> None:
        tiles = ttk.Frame(self)
        tiles.pack(fill="x", pady=(0, 12))
        self.tiles = {}
        for i, (key, caption, target) in enumerate((("apps", "Locked apps", "apps"), ("usb", "USB storage", "usb"),
                                                     ("idle", "Idle lock", "usb"), ("face", "Face unlock", "face"))):
            outer, body = make_card(tiles, pad=14)
            outer.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 10, 0))
            tiles.columnconfigure(i, weight=1, uniform="tile")
            value, detail = tk.StringVar(), tk.StringVar()
            ttk.Label(body, text=caption, style="CardMuted.TLabel").pack(anchor="w")
            ttk.Label(body, textvariable=value, style="Big.TLabel").pack(anchor="w")
            ttk.Label(body, textvariable=detail, style="CardMuted.TLabel").pack(anchor="w")
            for w in (outer, body, *body.winfo_children()):
                w.bind("<Button-1>", lambda _e, t=target: self.app.show_page(t))
            self.tiles[key] = (value, detail)

        mid = ttk.Frame(self)
        mid.pack(fill="x", pady=(0, 12))
        mid.columnconfigure(0, weight=3)
        mid.columnconfigure(1, weight=2)
        outer, body = make_card(mid, "Last 7 days")
        outer.grid(row=0, column=0, sticky="nsew")
        self.chart = tk.Canvas(body, height=120, bg="white", highlightthickness=0)
        self.chart.pack(fill="x")
        self.chart.bind("<Configure>", lambda _e: self._draw())
        legend = ttk.Frame(body, style="Card.TFrame")
        legend.pack(anchor="w", pady=(4, 0))
        for color, text in ((P["good"], "Unlocked"), (P["bad"], "Denied")):
            tk.Label(legend, bg=color, width=2).pack(side="left")
            ttk.Label(legend, text=" " + text + "   ", style="CardMuted.TLabel").pack(side="left")
        self._days = []

        outer, body = make_card(mid, "Protection")
        outer.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.pill = make_pill(body)
        self.pill.pack(anchor="w")
        self.protect_btn = ttk.Button(body, command=self.toggle_protection)
        self.protect_btn.pack(fill="x", pady=(10, 4))
        self.chain_var = tk.StringVar()
        ttk.Label(body, textvariable=self.chain_var, style="CardMuted.TLabel", wraplength=240).pack(anchor="w", pady=(6, 0))
        ttk.Button(body, text="Verify log now", command=self.verify).pack(fill="x", pady=(6, 0))
        ttk.Button(body, text="Lock Windows now", command=self.app.lock_windows).pack(fill="x", pady=(6, 0))

        outer, body = make_card(self, "Recent activity")
        outer.pack(fill="both", expand=True)
        frame, self.tree = make_tree(body, [("time", "Time", 170, False), ("event", "Event", 190, False),
                                            ("detail", "Detail", 400, True)], height=8)
        frame.pack(fill="both", expand=True)

    def _draw(self) -> None:
        if self._days:
            draw_bars(self.chart, self._days)

    def refresh(self) -> None:
        s = dashdata.summary(self.ctx)
        apps = s["apps"]
        self.tiles["apps"][0].set(str(len(apps)))
        self.tiles["apps"][1].set("none yet" if not apps else apps[0] + (f" +{len(apps) - 1} more" if len(apps) > 1 else ""))
        self.tiles["usb"][0].set(s["usb_status"].capitalize())
        self.tiles["usb"][1].set("Wanted: " + ("blocked" if s["usb_wanted"] else "allowed"))
        self.tiles["idle"][0].set("Off" if s["idle_minutes"] == 0 else f"{s['idle_minutes']:g} min")
        self.tiles["idle"][1].set("Windows auto-lock")
        self.tiles["face"][0].set("On" if s["face_enabled"] else "Off")
        self.tiles["face"][1].set(f"{s['face_samples']} sample(s)")
        running = self.app.runtime.running
        set_pill(self.pill, "PROTECTION ACTIVE" if running else "PROTECTION PAUSED", P["good"] if running else P["warn"])
        self.protect_btn.configure(text="Pause protection" if running else "Resume protection")
        self.chain_var.set("Audit log integrity: intact" if s["chain_ok"]
                           else f"Audit log integrity: BROKEN at entry {s['chain_bad']}")
        self._days = dashdata.activity_by_day(self.ctx.db, 7)
        self._draw()
        fill_events(self.tree, dashdata.query_events(self.ctx.db, limit=12))

    def toggle_protection(self) -> None:
        runtime = self.app.runtime
        if runtime.running:
            if not self.app.confirm_password("pause protection"):
                return
            runtime.stop()
        else:
            runtime.start()
        self.refresh()

    def verify(self) -> None:
        ok, bad = self.ctx.audit.verify()
        (messagebox.showinfo if ok else messagebox.showwarning)(
            "Audit log", "The audit chain is intact." if ok else f"The audit chain is BROKEN at entry {bad}.")
        self.refresh()


# --------------------------------------------------------------------------------------------
class AppsPage(Page):
    title = "Locked apps"

    def build(self) -> None:
        outer, body = make_card(self, "Lock another app")
        outer.pack(fill="x")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x")
        self.name_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.name_var, width=30)
        entry.pack(side="left")
        entry.bind("<Return>", lambda _e: self.add_typed())
        ttk.Button(row, text="Lock", style="Accent.TButton", command=self.add_typed).pack(side="left", padx=6)
        ttk.Button(row, text="Browse for .exe...", command=self.browse).pack(side="left")
        ttk.Button(row, text="Pick a running app...", command=self.pick_running).pack(side="left", padx=6)
        self.msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=700)
        self.msg.pack(anchor="w", pady=(8, 0))
        ttk.Label(body, style="CardMuted.TLabel", wraplength=700, text=(
            "A locked app is frozen the moment it starts until you enter the Gatekeeper password (or your face "
            "matches). Windows system programs and command prompts cannot be locked, so you can't lock yourself out."
        )).pack(anchor="w", pady=(4, 0))

        outer, body = make_card(self, "Currently locked")
        outer.pack(fill="both", expand=True, pady=(12, 0))
        frame, self.tree = make_tree(body, [("name", "Program", 300, True), ("added", "Locked since", 200, False)], height=9)
        frame.pack(fill="both", expand=True)
        ttk.Button(body, text="Unlock (remove) selected", command=self.remove_selected).pack(anchor="e", pady=(8, 0))

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for name, added in dashdata.locked_apps_detailed(self.ctx.db):
            self.tree.insert("", "end", values=(name, added))

    def _say(self, text: str, error: bool = False) -> None:
        self.msg.configure(text=text, foreground=P["bad"] if error else P["good"])

    def _add(self, raw: str) -> bool:
        name, error = dashdata.validate_app(raw)
        if error:
            self._say(error, True)
            return False
        self.ctx.db.add_app(name)
        self.ctx.audit.record("app_added", name)
        self._say(f"Locked {name}.")
        return True

    def add_typed(self) -> None:
        if self._add(self.name_var.get()):
            self.name_var.set("")
        self.refresh()

    def browse(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Choose a program",
                                          filetypes=[("Programs", "*.exe"), ("All files", "*.*")])
        if path:
            self._add(path)
            self.refresh()

    def pick_running(self) -> None:
        win = tk.Toplevel(self)
        win.title("Running programs")
        win.transient(self.winfo_toplevel())
        center(win, 380, 480)
        ttk.Label(win, text="Choose programs to lock:", padding=(12, 12, 12, 4)).pack(anchor="w")
        search = tk.StringVar()
        ttk.Entry(win, textvariable=search).pack(fill="x", padx=12)
        listbox = tk.Listbox(win, selectmode="extended", activestyle="none", exportselection=False)
        listbox.pack(fill="both", expand=True, padx=12, pady=8)
        names = dashdata.running_apps(exclude=set(self.ctx.db.list_apps()))

        def fill(*_):
            listbox.delete(0, "end")
            needle = search.get().strip().lower()
            for n in names:
                if needle in n:
                    listbox.insert("end", n)

        search.trace_add("write", fill)
        fill()

        def lock_selected():
            for index in listbox.curselection():
                self._add(listbox.get(index))
            win.destroy()
            self.refresh()

        row = ttk.Frame(win, padding=(12, 0, 12, 12))
        row.pack(fill="x")
        ttk.Button(row, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(row, text="Lock selected", style="Accent.TButton", command=lock_selected).pack(side="right", padx=6)

    def remove_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            self._say("Select a program in the list first.", True)
            return
        name = self.tree.item(selection[0], "values")[0]
        if messagebox.askyesno("Unlock app", f"Stop locking {name}?", parent=self):
            self.ctx.db.remove_app(name)
            self.ctx.audit.record("app_removed", name)
            self._say(f"{name} is no longer locked.")
            self.refresh()


# --------------------------------------------------------------------------------------------
class UsbIdlePage(Page):
    title = "USB and idle lock"

    def build(self) -> None:
        outer, body = make_card(self, "USB storage")
        outer.pack(fill="x")
        self.usb_var, self.admin_var = tk.StringVar(), tk.StringVar()
        ttk.Label(body, textvariable=self.usb_var, style="Card.TLabel", font=(FONT, 12, "bold")).pack(anchor="w")
        ttk.Label(body, textvariable=self.admin_var, style="CardMuted.TLabel").pack(anchor="w", pady=(2, 8))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(anchor="w")
        ttk.Button(row, text="Block USB storage", style="Accent.TButton", command=lambda: self.set_usb(True)).pack(side="left")
        ttk.Button(row, text="Allow USB storage", command=lambda: self.set_usb(False)).pack(side="left", padx=6)
        self.usb_msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=700)
        self.usb_msg.pack(anchor="w", pady=(8, 0))
        ttk.Label(body, style="CardMuted.TLabel", wraplength=700, text=(
            "Blocking stops new pen drives and external disks from mounting. Keyboards, mice and drives that are already "
            "plugged in keep working. Changing this needs Administrator rights.")).pack(anchor="w", pady=(4, 0))

        outer, body = make_card(self, "Idle lock")
        outer.pack(fill="x", pady=(12, 0))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(anchor="w")
        ttk.Label(row, text="Lock Windows after", style="Card.TLabel").pack(side="left")
        self.idle_var = tk.StringVar()
        ttk.Spinbox(row, from_=0, to=1440, increment=5, width=6, textvariable=self.idle_var).pack(side="left", padx=6)
        ttk.Label(row, text="idle minutes (0 = off)", style="Card.TLabel").pack(side="left")
        ttk.Button(row, text="Apply", style="Accent.TButton", command=self.apply_idle).pack(side="left", padx=12)
        ttk.Button(row, text="Lock Windows now", command=self.app.lock_windows).pack(side="left")
        self.idle_msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=700)
        self.idle_msg.pack(anchor="w", pady=(8, 0))
        ttk.Label(body, style="CardMuted.TLabel", wraplength=700, text=(
            "This uses the real Windows lock screen, so you sign back in with your Windows password, not the "
            "Gatekeeper password.")).pack(anchor="w", pady=(4, 0))

    def refresh(self) -> None:
        status = dashdata.usb_status(self.ctx)
        self.usb_var.set(f"USB storage is currently: {status.upper()}")
        self.admin_var.set("Gatekeeper is running as Administrator." if winapi.is_admin()
                           else "Gatekeeper is not running as Administrator (needed to change this).")
        self.idle_var.set(f"{float(self.ctx.db.get_setting('idle_lock_minutes', 0)):g}")

    def _say(self, label, text, error=False) -> None:
        label.configure(text=text, foreground=P["bad"] if error else P["good"])

    def set_usb(self, block: bool) -> None:
        from .usb import UsbPolicy
        policy = UsbPolicy(self.ctx)
        try:
            policy.block() if block else policy.allow()
        except PermissionError:
            if messagebox.askyesno(
                    "Administrator needed",
                    "Changing USB storage needs Administrator rights.\n\n"
                    "Restart Gatekeeper as Administrator now? Protection restarts with it.", parent=self):
                self.app.relaunch_elevated()
            return
        except Exception as exc:
            self._say(self.usb_msg, f"Could not change USB storage: {exc}", True)
            return
        suffix = " (dev mode: simulated, registry untouched)" if self.ctx.dev else ""
        self._say(self.usb_msg, ("USB storage blocked." if block else "USB storage allowed.") + suffix)
        self.refresh()

    def apply_idle(self) -> None:
        try:
            minutes = dashdata.set_idle_minutes(self.ctx, self.idle_var.get())
        except ValueError as exc:
            self._say(self.idle_msg, str(exc), True)
            return
        self.app.runtime.apply_idle_setting()
        self._say(self.idle_msg, "Idle lock is off." if minutes == 0 else f"Windows will lock after {minutes:g} idle minute(s).")


# --------------------------------------------------------------------------------------------
class FacePage(Page):
    title = "Face unlock"

    def build(self) -> None:
        self.session, self.mode, self.enroller, self._photo, self._after = None, None, None, None, None
        ttk.Label(self, style="Warn.TLabel", wraplength=760, justify="left", text=(
            "Face unlock is a convenience, not strong security. It has no liveness check yet, so a good photo or video "
            "of you may unlock apps. Your password is the real lock.")).pack(fill="x", pady=(0, 12))
        cols = ttk.Frame(self)
        cols.pack(fill="both", expand=True)
        cols.columnconfigure(0, weight=3)
        cols.columnconfigure(1, weight=2)

        outer, body = make_card(cols, "Camera")
        outer.grid(row=0, column=0, sticky="nsew")
        self.preview = tk.Label(body, text="Camera off", bg="#111827", fg="#9ca3af", width=52, height=16)
        self.preview.pack()
        self.status_var = tk.StringVar(value="")
        ttk.Label(body, textvariable=self.status_var, style="Card.TLabel", font=(FONT, 11, "bold")).pack(anchor="w", pady=(8, 0))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(anchor="w", pady=(8, 0))
        self.enroll_btn = ttk.Button(row, text="Enroll my face", style="Accent.TButton", command=self.start_enroll)
        self.enroll_btn.pack(side="left")
        self.test_btn = ttk.Button(row, text="Test recognition", command=self.start_test)
        self.test_btn.pack(side="left", padx=6)
        self.stop_btn = ttk.Button(row, text="Stop camera", command=self.stop)
        self.stop_btn.pack(side="left")
        opts = ttk.Frame(body, style="Card.TFrame")
        opts.pack(anchor="w", pady=(8, 0))
        ttk.Label(opts, text="Samples:", style="Card.TLabel").pack(side="left")
        self.samples_var = tk.StringVar(value="5")
        ttk.Spinbox(opts, from_=3, to=10, width=4, textvariable=self.samples_var).pack(side="left", padx=6)
        self.snap_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text="Keep encrypted face snapshots", variable=self.snap_var).pack(side="left", padx=8)

        outer, body = make_card(cols, "Settings")
        outer.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.samples_info = tk.StringVar()
        ttk.Label(body, textvariable=self.samples_info, style="Card.TLabel").pack(anchor="w")
        self.enabled_var = tk.BooleanVar()
        ttk.Checkbutton(body, text="Allow face unlock", variable=self.enabled_var).pack(anchor="w", pady=(8, 4))
        self.thr_var, self.timeout_var = tk.DoubleVar(), tk.DoubleVar()
        self.thr_text, self.timeout_text = tk.StringVar(), tk.StringVar()
        ttk.Label(body, text="Strictness", style="Card.TLabel").pack(anchor="w", pady=(8, 0))
        ttk.Scale(body, from_=THRESHOLD_RANGE[0], to=THRESHOLD_RANGE[1], variable=self.thr_var,
                  command=lambda v: self.thr_text.set(f"{float(v):.2f}  (higher = stricter)")).pack(fill="x")
        ttk.Label(body, textvariable=self.thr_text, style="CardMuted.TLabel").pack(anchor="w")
        ttk.Label(body, text="Give up after (seconds)", style="Card.TLabel").pack(anchor="w", pady=(8, 0))
        ttk.Scale(body, from_=2, to=30, variable=self.timeout_var,
                  command=lambda v: self.timeout_text.set(f"{float(v):.0f} s")).pack(fill="x")
        ttk.Label(body, textvariable=self.timeout_text, style="CardMuted.TLabel").pack(anchor="w")
        ttk.Button(body, text="Save settings", style="Accent.TButton", command=self.save).pack(fill="x", pady=(12, 4))
        ttk.Button(body, text="Delete face data...", style="Danger.TButton", command=self.delete).pack(fill="x")
        self.msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=260)
        self.msg.pack(anchor="w", pady=(8, 0))

    # -- settings -----------------------------------------------------------------------------
    def refresh(self) -> None:
        enabled, threshold, timeout = dashdata.face_options(self.ctx.db)
        with self.ctx.db.lock:
            count = self.ctx.db.conn.execute("SELECT COUNT(*) FROM face_samples").fetchone()[0]
        self.samples_info.set(f"{count} face sample(s) enrolled" if count else "No face enrolled yet")
        self.enabled_var.set(enabled)
        self.thr_var.set(threshold)
        self.timeout_var.set(timeout)
        self.thr_text.set(f"{threshold:.2f}  (higher = stricter)")
        self.timeout_text.set(f"{timeout:.0f} s")
        self._buttons(idle=self.session is None)

    def _say(self, text: str, error: bool = False) -> None:
        self.msg.configure(text=text, foreground=P["bad"] if error else P["good"])

    def save(self) -> None:
        try:
            warning = dashdata.set_face_options(self.ctx, self.enabled_var.get(),
                                                round(self.thr_var.get(), 2), round(self.timeout_var.get()))
        except ValueError as exc:
            self._say(str(exc), True)
            return
        self._say("Saved. Applies to the next unlock prompt." + (" " + warning if warning else ""), bool(warning))

    def delete(self) -> None:
        if not self.app.confirm_password("delete your face data"):
            return
        from .face_store import FaceStore
        self.stop()
        FaceStore(self.ctx.db, self.ctx.keys).clear()
        self.ctx.audit.record("face_cleared")
        self._say("Face data deleted.")
        self.refresh()

    # -- camera sessions ------------------------------------------------------------------------
    def _buttons(self, idle: bool) -> None:
        self.enroll_btn.configure(state="normal" if idle else "disabled")
        self.test_btn.configure(state="normal" if idle else "disabled")
        self.stop_btn.configure(state="disabled" if idle else "normal")

    def _begin(self, process, mode: str, seconds: float) -> None:
        self.mode, self.deadline = mode, time.monotonic() + seconds
        self.session = CameraSession(process)
        self.session.start()
        self._buttons(idle=False)
        self._poll()

    def start_enroll(self) -> None:
        from .enroll import MESSAGES, Enroller
        from .face_store import FaceStore
        try:
            engine = self.app.runtime.engine()
            samples = int(self.samples_var.get())
        except Exception as exc:
            self._say(f"Face models unavailable: {exc}", True)
            return
        enroller = self.enroller = Enroller(engine, FaceStore(self.ctx.db, self.ctx.keys), samples,
                                            snapshots=self.snap_var.get())

        def process(frame):
            status = enroller.offer(frame)
            return f"{enroller.collected}/{enroller.target}   {MESSAGES[status]}", enroller.done

        self._say("Look at the camera. Only one face in view.")
        self._begin(process, "enroll", 120)

    def start_test(self) -> None:
        from .face_store import FaceStore
        from .matcher import FaceMatcher
        enrolled = FaceStore(self.ctx.db, self.ctx.keys).embeddings()
        if not enrolled:
            self._say("Enroll your face first.", True)
            return
        try:
            matcher = FaceMatcher(self.app.runtime.engine(), enrolled, round(self.thr_var.get(), 2))
        except Exception as exc:
            self._say(f"Face models unavailable: {exc}", True)
            return

        def process(frame):
            score = matcher.score(frame)
            if score is None:
                return "Need exactly one face in view", False
            return f"score {score:.2f}  /  needs {matcher.threshold:.2f}   " + ("MATCH" if score >= matcher.threshold else "no match"), False

        self._say("Move the Strictness slider and watch the score; Test uses the slider value.")
        self._begin(process, "test", 60)

    def _poll(self) -> None:
        session = self.session
        if session is None:
            return
        png = session.frame_if_new()
        if png:
            self._photo = tk.PhotoImage(data=png)
            self.preview.configure(image=self._photo, text="", width=0, height=0)
        self.status_var.set(session.status)
        if session.error:
            self.stop()
            self._say(f"Camera problem: {session.error}", True)
        elif session.done and self.mode == "enroll":
            self._finish_enroll()
        elif time.monotonic() > self.deadline:
            self.stop()
            self._say("Timed out." + (" Nothing was saved." if self.mode == "enroll" else ""), True)
        else:
            self._after = self.after(60, self._poll)

    def _finish_enroll(self) -> None:
        enroller = self.enroller
        self.stop()
        try:
            count = enroller.commit()
        except RuntimeError as exc:
            self._say(str(exc), True)
            return
        self.ctx.audit.record("face_enrolled", f"{count} samples")
        self._say(f"Enrolled {count} samples. They are stored encrypted.")
        self.refresh()

    def stop(self) -> None:
        if self._after is not None:
            self.after_cancel(self._after)
            self._after = None
        if self.session is not None:
            self.session.stop()
            self.session = None
        self._photo = None
        self.preview.configure(image="", text="Camera off", width=52, height=16)
        self.status_var.set("")
        self._buttons(idle=True)

    def leave(self) -> None:
        self.stop()


# --------------------------------------------------------------------------------------------
RANGES = {"All time": None, "Last hour": 1, "Last 24 hours": 24, "Last 7 days": 24 * 7, "Last 30 days": 24 * 30}


class LogPage(Page):
    title = "Activity log"

    def build(self) -> None:
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 10))
        self.type_var, self.range_var, self.search_var = (tk.StringVar(value="All events"),
                                                          tk.StringVar(value="Last 7 days"), tk.StringVar())
        self.type_box = ttk.Combobox(bar, textvariable=self.type_var, state="readonly", width=22)
        self.type_box.pack(side="left")
        range_box = ttk.Combobox(bar, textvariable=self.range_var, values=list(RANGES), state="readonly", width=13)
        range_box.pack(side="left", padx=6)
        search = ttk.Entry(bar, textvariable=self.search_var, width=18)
        search.pack(side="left")
        for widget in (self.type_box, range_box):
            widget.bind("<<ComboboxSelected>>", lambda _e: self.refresh())
        search.bind("<Return>", lambda _e: self.refresh())
        ttk.Button(bar, text="Search", command=self.refresh).pack(side="left", padx=6)
        ttk.Button(bar, text="Export CSV...", command=self.export).pack(side="right")

        outer, body = make_card(self)
        outer.pack(fill="both", expand=True)
        frame, self.tree = make_tree(body, [("time", "Time", 170, False), ("event", "Event", 190, False),
                                            ("detail", "Detail", 420, True)], height=16)
        frame.pack(fill="both", expand=True)
        foot = ttk.Frame(self)
        foot.pack(fill="x", pady=(8, 0))
        self.count_var = tk.StringVar()
        ttk.Label(foot, textvariable=self.count_var, style="Muted.TLabel").pack(side="left")
        ttk.Button(foot, text="Reset log chain...", style="Danger.TButton", command=self.reset).pack(side="right")
        ttk.Button(foot, text="Remove old entries", command=self.prune).pack(side="right", padx=6)
        ttk.Button(foot, text="Verify integrity", command=self.verify).pack(side="right")
        self._labels = {}

    def refresh(self) -> None:
        types = dashdata.event_types(self.ctx.db)
        self._labels = {dashdata.describe(t): t for t in types}
        self.type_box.configure(values=["All events"] + sorted(self._labels))
        event = self._labels.get(self.type_var.get())
        rows = dashdata.query_events(self.ctx.db, event=event, text=self.search_var.get(),
                                     hours=RANGES[self.range_var.get()], limit=1000)
        fill_events(self.tree, rows)
        self.count_var.set(f"Showing {len(rows)} of {dashdata.count_events(self.ctx.db)} entries (newest first)")

    def export(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv", initialfile="gatekeeper-log.csv",
                                            filetypes=[("CSV", "*.csv")])
        if path:
            count = self.ctx.audit.export_csv(path)
            messagebox.showinfo("Export", f"Exported {count} entries.", parent=self)

    def verify(self) -> None:
        ok, bad = self.ctx.audit.verify()
        (messagebox.showinfo if ok else messagebox.showwarning)(
            "Audit log", "The audit chain is intact." if ok else f"The audit chain is BROKEN at entry {bad}.", parent=self)

    def prune(self) -> None:
        days = int(self.ctx.db.get_setting("log_retention_days", 90))
        if days <= 0:
            messagebox.showinfo("Retention", "Retention is off, so old entries are kept forever.\n"
                                "Change it in Settings.", parent=self)
        elif messagebox.askyesno("Remove old entries", f"Delete entries older than {days} days?", parent=self):
            removed = self.ctx.audit.prune(days)
            messagebox.showinfo("Retention", f"Removed {removed} entries.", parent=self)
            self.refresh()

    def reset(self) -> None:
        if not messagebox.askyesno(
                "Reset log chain", "This starts a brand-new log. The current one is saved first.\n\nContinue?", parent=self):
            return
        if not self.app.confirm_password("reset the log"):
            return
        backup = self.ctx.directory / "audit-before-reset.csv"
        self.ctx.audit.export_csv(backup)
        self.ctx.audit.reset()
        messagebox.showinfo("Log reset", f"The old log was saved to:\n{backup}", parent=self)
        self.refresh()


# --------------------------------------------------------------------------------------------
class SettingsPage(Page):
    title = "Settings"

    def build(self) -> None:
        outer, body = make_card(self, "Change password")
        outer.pack(fill="x")
        self.cur, self.new, self.rep = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, var in (("Current password", self.cur), ("New password", self.new), ("Repeat new password", self.rep)):
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, style="Card.TLabel", width=20).pack(side="left")
            ttk.Entry(row, textvariable=var, show="*", width=30).pack(side="left")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Change password", style="Accent.TButton", command=self.change_password).pack(side="left")
        self.pw_msg = ttk.Label(row, style="CardMuted.TLabel")
        self.pw_msg.pack(side="left", padx=10)
        ttk.Label(body, style="CardMuted.TLabel", text=f"At least {MIN_PASSWORD_LEN} characters. There is no recovery "
                  "backdoor: if you forget it, see Recovery in the README.").pack(anchor="w", pady=(6, 0))

        outer, body = make_card(self, "Behaviour")
        outer.pack(fill="x", pady=(12, 0))
        self.autolock_var, self.retention_var = tk.StringVar(), tk.StringVar()
        for label, var, high, hint in (
                ("Lock this window after", self.autolock_var, 240, "idle minutes (0 = never)"),
                ("Keep activity log for", self.retention_var, 3650, "days (0 = forever)")):
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, style="Card.TLabel", width=22).pack(side="left")
            ttk.Spinbox(row, from_=0, to=high, width=7, textvariable=var).pack(side="left")
            ttk.Label(row, text=" " + hint, style="CardMuted.TLabel").pack(side="left")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Save", style="Accent.TButton", command=self.save_behaviour).pack(side="left")
        self.beh_msg = ttk.Label(row, style="CardMuted.TLabel")
        self.beh_msg.pack(side="left", padx=10)

        outer, body = make_card(self, "About and recovery")
        outer.pack(fill="x", pady=(12, 0))
        self.about = tk.StringVar()
        ttk.Label(body, textvariable=self.about, style="Card.TLabel", justify="left", wraplength=700).pack(anchor="w")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(anchor="w", pady=(8, 0))
        ttk.Button(row, text="Open data folder", command=self.open_folder).pack(side="left")
        ttk.Button(row, text="Release frozen apps", command=self.release).pack(side="left", padx=6)
        ttk.Label(body, style="CardMuted.TLabel", wraplength=700, text=(
            "Gatekeeper deters casual access. See docs/LIMITATIONS.md for what it cannot stop."
        )).pack(anchor="w", pady=(8, 0))

    def refresh(self) -> None:
        self.autolock_var.set(f"{dashdata.autolock_minutes(self.ctx.db):g}")
        self.retention_var.set(str(int(self.ctx.db.get_setting("log_retention_days", 90))))
        self.about.set(f"Mode: {'DEV (nothing is killed, blocked or locked)' if self.ctx.dev else 'enforcing'}\n"
                       f"Data folder: {self.ctx.directory}")

    def change_password(self) -> None:
        ok, message = dashdata.change_password(self.ctx, self.cur.get(), self.new.get(), self.rep.get())
        self.pw_msg.configure(text=message, foreground=P["good"] if ok else P["bad"])
        if ok:
            self.cur.set("")
            self.new.set("")
            self.rep.set("")

    def save_behaviour(self) -> None:
        try:
            dashdata.set_autolock_minutes(self.ctx, self.autolock_var.get())
            dashdata.set_retention_days(self.ctx, self.retention_var.get())
        except ValueError as exc:
            self.beh_msg.configure(text=str(exc), foreground=P["bad"])
            return
        self.beh_msg.configure(text="Saved.", foreground=P["good"])

    def open_folder(self) -> None:
        try:
            os.startfile(self.ctx.directory)  # Windows only
        except (AttributeError, OSError):
            messagebox.showinfo("Data folder", str(self.ctx.directory), parent=self)

    def release(self) -> None:
        from .guard import release_suspended
        messagebox.showinfo("Released", f"Resumed {release_suspended(self.ctx)} frozen process(es).", parent=self)


PAGES = [("dashboard", "Dashboard", DashboardPage), ("apps", "Locked apps", AppsPage),
         ("usb", "USB and idle lock", UsbIdlePage), ("face", "Face unlock", FacePage),
         ("log", "Activity log", LogPage), ("settings", "Settings", SettingsPage)]
