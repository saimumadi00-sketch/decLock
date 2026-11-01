"""The dashboard pages. Each page talks to the same db/auth/audit objects as the CLI (through
dashdata), so settings changed here and on the command line always agree.

Every page is a ttk.Frame subclass of Page with three hooks the Dashboard calls:
  build()    once, to create the widgets
  refresh()  when the page is shown (and every 5 s for pages with auto_refresh)
  leave()    when another page is shown (stop cameras, timers, ...)
"""

import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import dashdata, face_anim, schedule, winapi
from .config import MIN_PASSWORD_LEN
from .gui_widgets import (BAR_SERIES, FONT, P, CameraSession, center, day_at, draw_bars, draw_hbars,
                          make_card, make_dot, make_pill, password_entry, set_empty, set_pill)
from .matcher import THRESHOLD_RANGE, TIMEOUT_RANGE, enrolment_current


class Page(ttk.Frame):
    title = ""            # shown as the page heading
    auto_refresh = False  # True: the Dashboard calls refresh() every 5 seconds while it's visible

    def __init__(self, parent, app):
        super().__init__(parent, padding=(24, 16))
        self.app, self.ctx = app, app.ctx  # app = the Dashboard (navigation, password prompts, runtime)
        ttk.Label(self, text=self.title, style="H1.TLabel").pack(anchor="w", pady=(0, 14))
        self.build()

    def build(self) -> None:
        pass

    def refresh(self) -> None:
        pass

    def leave(self) -> None:
        pass


def make_tree(parent, columns, height=10, empty=""):
    """Treeview with a scrollbar. `columns` = [(id, heading, width, stretch)]; `empty` is the hint
    shown (see set_empty) when the table has no rows."""
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
    # Row colours by severity; fill_events() tags each row with dashdata.severity(event).
    tree.tag_configure("good", foreground=P["good"])
    tree.tag_configure("bad", foreground=P["bad"])
    tree.tag_configure("warn", foreground=P["warn"])
    tree.empty_hint = ttk.Label(tree, text=empty, style="CardMuted.TLabel", wraplength=420,
                                justify="center") if empty else None
    return frame, tree


def fill_events(tree, rows) -> None:
    """Replace the tree's rows with audit-log rows (as returned by dashdata.query_events)."""
    tree.delete(*tree.get_children())
    set_empty(tree, not rows)
    for r in rows:
        tree.insert("", "end", values=(dashdata.local_time(r["ts"]), dashdata.describe(r["event"]), r["detail"]),
                    tags=(dashdata.severity(r["event"]),))


def show_verify_result(ctx, parent) -> None:
    """'Verify log now' / 'Verify integrity' buttons: run the chain check and say the result."""
    ok, bad = ctx.audit.verify()
    (messagebox.showinfo if ok else messagebox.showwarning)(
        "Audit log", "The audit chain is intact." if ok else f"The audit chain is BROKEN at entry {bad}.",
        parent=parent)


# --------------------------------------------------------------------------------------------
CHART_MODES = ("Unlocked vs denied", "Blocked starts", "Most-attempted apps")
BLOCKED_SERIES = (("blocked", "warn", "Blocked start"),)


def bind_click(widget, command) -> None:
    """Make a whole card (and everything inside it) clickable."""
    widget.bind("<Button-1>", lambda _e: command())
    widget.configure(cursor="hand2")
    for child in widget.winfo_children():  # children swallow clicks, so bind them too
        bind_click(child, command)


class DashboardPage(Page):
    title = "Dashboard"
    auto_refresh = True

    # (key, caption) of the status tiles across the top.
    TILES = (("apps", "Locked apps"), ("usb", "USB storage"), ("idle", "Idle lock"),
             ("face", "Face unlock"), ("fails", "Problems (24h)"))

    def build(self) -> None:
        # Holder for the first-run checklist (filled in by _refresh_checklist).
        self.check_holder = ttk.Frame(self)
        self.check_holder.pack(fill="x")
        self._check_sig = None  # what the checklist currently shows, to avoid rebuilding it every 5 s

        # -- status tiles: each opens the page (or filtered log) it summarises -------------------
        self.tiles_frame = ttk.Frame(self)
        self.tiles_frame.pack(fill="x", pady=(0, 12))
        self.tiles, self.tile_cards, self._cols = {}, [], 0
        targets = {"apps": lambda: self.app.show_page("apps"), "usb": lambda: self.app.show_page("usb"),
                   "idle": lambda: self.app.show_page("usb"), "face": lambda: self.app.show_page("face"),
                   "fails": lambda: self.app.open_log(severity="bad", range_label="Last 24 hours")}
        for key, caption in self.TILES:
            outer, body = make_card(self.tiles_frame, pad=14)
            head = ttk.Frame(body, style="Card.TFrame")
            head.pack(fill="x")
            dot = make_dot(head)  # coloured status dot, recoloured in refresh()
            dot.pack(side="left")
            ttk.Label(head, text=" " + caption, style="CardMuted.TLabel").pack(side="left")
            value, detail = tk.StringVar(), tk.StringVar()
            value_label = ttk.Label(body, textvariable=value, style="Big.TLabel")
            value_label.pack(anchor="w")
            ttk.Label(body, textvariable=detail, style="CardMuted.TLabel").pack(anchor="w")
            bind_click(outer, targets[key])
            self.tiles[key] = (value, detail, dot, value_label)
            self.tile_cards.append(outer)
        self.tiles_frame.bind("<Configure>", self._layout_tiles)  # re-flow when the window is resized
        self._layout_tiles()

        # -- 7-day chart (left) and protection controls (right) ---------------------------------
        mid = ttk.Frame(self)
        mid.pack(fill="x", pady=(0, 12))
        mid.columnconfigure(0, weight=3)
        mid.columnconfigure(1, weight=2)
        outer, body = make_card(mid)
        outer.grid(row=0, column=0, sticky="nsew")
        head = ttk.Frame(body, style="Card.TFrame")
        head.pack(fill="x", pady=(0, 8))
        ttk.Label(head, text="Last 7 days", style="CardTitle.TLabel").pack(side="left")
        self.mode_var = tk.StringVar(value=CHART_MODES[0])
        box = ttk.Combobox(head, textvariable=self.mode_var, values=CHART_MODES, state="readonly", width=20)
        box.pack(side="right")
        box.bind("<<ComboboxSelected>>", lambda _e: self._mode_changed())
        self.chart = tk.Canvas(body, height=120, bg=P["card"], highlightthickness=0)
        self.chart.pack(fill="x")
        self.chart.bind("<Configure>", lambda _e: self._draw())  # redraw at the new size
        self.chart.bind("<Button-1>", self._chart_click)
        self.legend = ttk.Frame(body, style="Card.TFrame")
        self.legend.pack(anchor="w", pady=(4, 0))
        self._days, self._top = [], []  # chart data, loaded in refresh() (not on every resize)
        self._build_legend()

        outer, body = make_card(mid, "Protection")
        outer.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        self.pill = make_pill(body)  # PROTECTION ACTIVE / PAUSED
        self.pill.pack(anchor="w")
        self.protect_btn = ttk.Button(body, command=self.toggle_protection)
        self.protect_btn.pack(fill="x", pady=(10, 4))
        self.chain_var = tk.StringVar()
        ttk.Label(body, textvariable=self.chain_var, style="CardMuted.TLabel", wraplength=240).pack(anchor="w", pady=(6, 0))
        ttk.Button(body, text="Verify log now", command=self.verify).pack(fill="x", pady=(6, 0))
        ttk.Button(body, text="Lock Windows now", command=self.app.lock_windows).pack(fill="x", pady=(6, 0))

        # -- newest log entries ---------------------------------------------------------------
        outer, body = make_card(self, "Recent activity")
        outer.pack(fill="both", expand=True)
        frame, self.tree = make_tree(body, [("time", "Time", 170, False), ("event", "Event", 190, False),
                                            ("detail", "Detail", 400, True)], height=8,
                                     empty="No activity yet. Lock an app and it will show up here.")
        frame.pack(fill="both", expand=True)

    # -- layout / chart -----------------------------------------------------------------------
    def _layout_tiles(self, _event=None) -> None:
        """Five tiles in a row when wide, wrapping to 3 or 2 per row on narrow windows."""
        width = self.tiles_frame.winfo_width()
        cols = 5 if width >= 760 else 3 if width >= 480 else 2
        if cols == self._cols:  # <Configure> fires constantly while resizing; only re-grid on change
            return
        self._cols = cols
        for i in range(len(self.tile_cards)):  # clear the old column weights first
            self.tiles_frame.columnconfigure(i, weight=0, uniform="")
        for i, card in enumerate(self.tile_cards):
            card.grid_forget()
            card.grid(row=i // cols, column=i % cols, sticky="nsew",
                      padx=(0 if i % cols == 0 else 10, 0), pady=(0 if i < cols else 10, 0))
        for c in range(cols):
            self.tiles_frame.columnconfigure(c, weight=1, uniform="tile")  # equal-width columns

    def _series(self):
        return BAR_SERIES if self.mode_var.get() == CHART_MODES[0] else BLOCKED_SERIES

    def _build_legend(self) -> None:
        for child in self.legend.winfo_children():
            child.destroy()
        if self.mode_var.get() == CHART_MODES[2]:
            ttk.Label(self.legend, text="Blocked starts since the log began", style="CardMuted.TLabel").pack(side="left")
            return
        for _key, color, text in self._series():
            tk.Label(self.legend, bg=P[color], width=2).pack(side="left")  # colour swatch
            ttk.Label(self.legend, text=" " + text + "   ", style="CardMuted.TLabel").pack(side="left")
        ttk.Label(self.legend, text="Click a day to see its log", style="CardMuted.TLabel").pack(side="left")

    def _mode_changed(self) -> None:
        self._build_legend()
        self._draw()

    def _draw(self) -> None:
        """Draw the chart for the selected mode from the data loaded by refresh()."""
        if self.mode_var.get() == CHART_MODES[2]:
            draw_hbars(self.chart, self._top)
            self.chart.configure(cursor="")
        elif self._days:
            draw_bars(self.chart, self._days, self._series())
            self.chart.configure(cursor="hand2")  # day columns are clickable

    def _chart_click(self, event) -> None:
        """Clicking a day column opens the Activity log filtered to that day."""
        index = day_at(self.chart, event.x)
        if index is not None and self.mode_var.get() != CHART_MODES[2] and index < len(self._days):
            self.app.open_log(day=self._days[index]["date"])

    # -- first-run checklist --------------------------------------------------------------------
    def _refresh_checklist(self) -> None:
        items = [] if dashdata.checklist_dismissed(self.ctx.db) else dashdata.checklist(self.ctx)
        if items and all(done for _l, done, _p in items):
            items = []  # everything done: hide it for good
        signature = tuple(items)
        if signature == self._check_sig:  # unchanged since the last refresh: keep the widgets
            return
        self._check_sig = signature
        for child in self.check_holder.winfo_children():
            child.destroy()
        if not items:
            return
        outer, body = make_card(self.check_holder, "Get started")
        outer.pack(fill="x", pady=(0, 12))
        for label, done, page in items:
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=("✓  " if done else "○  ") + label, style="Card.TLabel",
                      foreground=P["good"] if done else P["text"]).pack(side="left")
            if not done:
                ttk.Button(row, text="Open", style="Chip.TButton",
                           command=lambda p=page: self.app.show_page(p)).pack(side="right")
        ttk.Button(body, text="Dismiss checklist", style="Chip.TButton",
                   command=self._dismiss_checklist).pack(anchor="e", pady=(6, 0))

    def _dismiss_checklist(self) -> None:
        dashdata.dismiss_checklist(self.ctx.db)
        self._refresh_checklist()

    # -- data -----------------------------------------------------------------------------------
    def refresh(self) -> None:
        s = dashdata.summary(self.ctx)
        apps = s["apps"]
        usb = s["usb_status"]
        problems = s["problems24"]
        # key -> (big value, small detail line, status dot colour)
        values = {
            "apps": (str(len(apps)), "none yet" if not apps else apps[0] + (f" +{len(apps) - 1} more" if len(apps) > 1 else ""),
                     P["good"] if apps else P["warn"]),
            "usb": (usb.capitalize(), "Wanted: " + ("blocked" if s["usb_wanted"] else "allowed"),
                    P["good"] if usb == "blocked" else P["muted"]),
            "idle": ("Off" if s["idle_minutes"] == 0 else f"{s['idle_minutes']:g} min", "Windows auto-lock",
                     P["muted"] if s["idle_minutes"] == 0 else P["good"]),
            "face": ("On" if s["face_enabled"] else "Off",
                     f"{s['face_samples']} sample(s)" if s["face_current"] or not s["face_samples"] else "re-enrol needed",
                     P["good"] if s["face_enabled"] else P["muted"]),
            "fails": (str(problems), "wrong passwords, denials, ..." if problems else "all quiet",
                      P["bad"] if problems else P["good"]),
        }
        for key, (value, detail, color) in values.items():
            var, detail_var, dot, label = self.tiles[key]
            var.set(value)
            detail_var.set(detail)
            dot.configure(fg=color)
            label.configure(foreground=P["bad"] if key == "fails" and problems else P["text"])
        running = self.app.runtime.running
        set_pill(self.pill, "PROTECTION ACTIVE" if running else "PROTECTION PAUSED", P["good"] if running else P["warn"])
        self.protect_btn.configure(text="Pause protection" if running else "Resume protection")
        self.chain_var.set("Audit log integrity: intact" if s["chain_ok"]
                           else f"Audit log integrity: BROKEN at entry {s['chain_bad']}")
        self._days = dashdata.activity_by_day(self.ctx.db, 7)
        self._top = dashdata.top_apps(self.ctx.db)
        self._draw()
        self._refresh_checklist()
        fill_events(self.tree, dashdata.query_events(self.ctx.db, limit=12))

    def toggle_protection(self) -> None:
        self.app.toggle_protection()  # same rules as the tray menu (pausing needs the password)
        self.refresh()

    def verify(self) -> None:
        show_verify_result(self.ctx, self)
        self.refresh()


# --------------------------------------------------------------------------------------------
class AppsPage(Page):
    title = "Locked apps"

    def build(self) -> None:
        # -- add an app: type it, browse for it, pick it from running programs, or add a preset ----
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
        preset = ttk.Menubutton(row, text="Add a preset")
        menu = tk.Menu(preset, tearoff=False)
        for name, exes in dashdata.PRESETS.items():
            menu.add_command(label=f"{name} ({len(exes)} apps)", command=lambda n=name: self.add_preset(n))
        preset.configure(menu=menu)
        preset.pack(side="left")
        self.msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=700)  # result / error line
        self.msg.pack(anchor="w", pady=(8, 0))
        ttk.Label(body, style="CardMuted.TLabel", wraplength=700, text=(
            "A locked app is frozen the moment it starts until you enter the Gatekeeper password (or your face "
            "matches). Windows system programs and command prompts cannot be locked, so you can't lock yourself out."
        )).pack(anchor="w", pady=(4, 0))

        # -- the list of locked apps ----------------------------------------------------------
        outer, body = make_card(self, "Currently locked")
        outer.pack(fill="both", expand=True, pady=(12, 0))
        frame, self.tree = make_tree(body, [("name", "Program", 190, True), ("added", "Locked since", 150, False),
                                            ("schedule", "Locked during", 110, False),
                                            ("last", "Last attempt", 150, False), ("denied", "Denied", 60, False)],
                                     height=9, empty="No apps locked yet. Type a program name above, or add a preset.")
        frame.pack(fill="both", expand=True)
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(anchor="e", pady=(8, 0))
        ttk.Button(row, text="Set schedule for selected...", command=self.schedule_selected).pack(side="left")
        ttk.Button(row, text="Unlock (remove) selected", command=self.remove_selected).pack(side="left", padx=(6, 0))

    def refresh(self) -> None:
        self.tree.delete(*self.tree.get_children())
        rows = dashdata.locked_apps_overview(self.ctx.db)
        for row in rows:
            self.tree.insert("", "end", values=row)
        set_empty(self.tree, not rows)

    def _say(self, text: str, error: bool = False) -> None:
        self.msg.configure(text=text, foreground=P["bad"] if error else P["good"])

    def _add(self, raw: str) -> bool:
        """Validate and lock one app. Shows the result in the message line."""
        name, error = dashdata.lock_app(self.ctx, raw)
        if error:
            self._say(error, True)
            return False
        self._say(f"Locked {name}.")
        return True

    def add_typed(self) -> None:
        if self._add(self.name_var.get()):
            self.name_var.set("")
        self.refresh()

    def add_preset(self, preset: str) -> None:
        added = dashdata.add_preset(self.ctx, preset)
        self._say(f"Locked {len(added)} {preset.lower()} app(s)." if added else f"Every {preset.lower()} app is already locked.")
        self.refresh()

    def browse(self) -> None:
        path = filedialog.askopenfilename(parent=self, title="Choose a program",
                                          filetypes=[("Programs", "*.exe"), ("All files", "*.*")])
        if path:
            self._add(path)  # the name is locked, and the file is fingerprinted to catch renamed copies
            self.refresh()

    def pick_running(self) -> None:
        """Dialog listing running programs (searchable, multi-select)."""
        win = tk.Toplevel(self)
        win.title("Running programs")
        win.transient(self.winfo_toplevel())
        win.configure(bg=P["bg"])
        center(win, 380, 480)
        ttk.Label(win, text="Choose programs to lock:", padding=(12, 12, 12, 4)).pack(anchor="w")
        search = tk.StringVar()
        ttk.Entry(win, textvariable=search).pack(fill="x", padx=12)
        listbox = tk.Listbox(win, selectmode="extended", activestyle="none", exportselection=False,
                             bg=P["card"], fg=P["text"], highlightthickness=0)
        listbox.pack(fill="both", expand=True, padx=12, pady=8)
        names = dashdata.running_apps(exclude=set(self.ctx.db.list_apps()))

        def fill(*_):  # re-filter the list on every keystroke in the search box
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

    def _selected_name(self):
        selection = self.tree.selection()
        if not selection:
            self._say("Select a program in the list first.", True)
            return None
        return str(self.tree.item(selection[0], "values")[0])  # column 0 = program name

    def schedule_selected(self) -> None:
        """Dialog to lock the selected app only during a daily time window."""
        name = self._selected_name()
        if not name:
            return
        current = schedule.get(self.ctx.db, name)  # "HH:MM-HH:MM", or "" for always
        start, end = current.split("-") if current else ("09:00", "17:00")
        win = tk.Toplevel(self)
        win.title("Lock schedule")
        win.transient(self.winfo_toplevel())
        win.resizable(False, False)
        win.configure(bg=P["bg"])
        frame = ttk.Frame(win, padding=18, style="Card.TFrame")
        frame.pack()
        ttk.Label(frame, text=f"When should {name} be locked?", style="Card.TLabel").pack(anchor="w")
        always = tk.BooleanVar(value=not current)
        start_var, end_var = tk.StringVar(value=start), tk.StringVar(value=end)
        ttk.Checkbutton(frame, text="Always (no schedule)", variable=always).pack(anchor="w", pady=(8, 4))
        row = ttk.Frame(frame, style="Card.TFrame")
        row.pack(anchor="w")
        ttk.Label(row, text="Locked from", style="Card.TLabel").pack(side="left")
        ttk.Entry(row, textvariable=start_var, width=7).pack(side="left", padx=6)
        ttk.Label(row, text="to", style="Card.TLabel").pack(side="left")
        ttk.Entry(row, textvariable=end_var, width=7).pack(side="left", padx=6)
        ttk.Label(frame, text="24-hour times. 22:00 to 06:00 runs overnight. Outside the window the app opens freely.",
                  style="CardMuted.TLabel", wraplength=300).pack(anchor="w", pady=(6, 0))
        error = ttk.Label(frame, style="Err.TLabel", wraplength=300)
        error.pack(anchor="w")

        def save() -> None:
            try:
                window = dashdata.set_app_schedule(self.ctx, name, start_var.get(), end_var.get(), always.get())
            except ValueError as exc:  # malformed times: keep the dialog open and explain
                error.configure(text=str(exc))
                return
            win.destroy()
            self._say(f"{name} is locked {'always' if not window else 'during ' + window}.")
            self.refresh()

        buttons = ttk.Frame(frame, style="Card.TFrame")
        buttons.pack(anchor="e", pady=(10, 0))
        ttk.Button(buttons, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(buttons, text="Save", style="Accent.TButton", command=save).pack(side="right", padx=6)
        self.save_schedule = save  # exposed for tests
        self.schedule_vars = (always, start_var, end_var)
        self.schedule_window = win

    def remove_selected(self) -> None:
        name = self._selected_name()
        if not name:
            return
        # Removing a locked app switches its protection off, just like pausing does, so it needs
        # the password too (someone at an unattended, unlocked dashboard can't quietly do it).
        if self.app.confirm_password(f"stop locking {name}"):
            dashdata.remove_app(self.ctx, name)
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
            # Not elevated: offer to restart as Administrator (UAC prompt) instead of failing.
            if messagebox.askyesno(
                    "Administrator needed",
                    "Changing USB storage needs Administrator rights.\n\n"
                    "Restart Gatekeeper as Administrator now? Protection restarts with it.", parent=self):
                self.app.relaunch_elevated()
            return
        except Exception as exc:
            self._say(self.usb_msg, f"Could not change USB storage: {exc}", True)
            return
        self.ctx.db.set_setting("usb_choice_made", "1")  # ticks off the first-run checklist item
        suffix = " (dev mode: simulated, registry untouched)" if self.ctx.dev else ""
        self._say(self.usb_msg, ("USB storage blocked." if block else "USB storage allowed.") + suffix)
        self.refresh()

    def apply_idle(self) -> None:
        try:
            minutes = dashdata.set_idle_minutes(self.ctx, self.idle_var.get())
        except ValueError as exc:
            self._say(self.idle_msg, str(exc), True)
            return
        self.app.runtime.apply_idle_setting()  # restart the idle watcher with the new value
        self._say(self.idle_msg, "Idle lock is off." if minutes == 0 else f"Windows will lock after {minutes:g} idle minute(s).")


# --------------------------------------------------------------------------------------------
class FacePage(Page):
    title = "Face unlock"

    def build(self) -> None:
        # session: the running CameraSession (or None); mode: "enroll" / "test"; _after: the poll timer
        self.session, self.mode, self.enroller, self._photo, self._after = None, None, None, None, None
        self.matched = False  # test mode: did the latest frame match? (set on the camera thread)
        ttk.Label(self, style="Warn.TLabel", wraplength=760, justify="left", text=(
            "Face unlock checks that the face is real (photos and screens are rejected) and asks for two random head "
            "movements. It is still not as strong as your password: a realistic mask or a skilled deepfake could "
            "get through.")).pack(fill="x", pady=(0, 12))
        cols = ttk.Frame(self)
        cols.pack(fill="both", expand=True)
        cols.columnconfigure(0, weight=3)
        cols.columnconfigure(1, weight=2)

        # -- left: camera preview, animation, start/stop buttons --------------------------------
        outer, body = make_card(cols, "Camera")
        outer.grid(row=0, column=0, sticky="nsew")
        self.preview = tk.Label(body, text="Camera off", bg="#111827", fg="#9ca3af", width=52, height=16)
        self.preview.pack()
        status_row = ttk.Frame(body, style="Card.TFrame")
        status_row.pack(fill="x", pady=(8, 0))
        self.anim = face_anim.FaceIDAnimation(status_row, size=88)
        self.anim.pack(side="left", padx=(0, 12))
        self.status_var = tk.StringVar(value="")
        ttk.Label(status_row, textvariable=self.status_var, style="Card.TLabel", font=(FONT, 11, "bold"),
                  wraplength=330).pack(side="left", anchor="w")
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

        # -- right: face unlock settings ------------------------------------------------------
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
        ttk.Scale(body, from_=TIMEOUT_RANGE[0], to=TIMEOUT_RANGE[1], variable=self.timeout_var,
                  command=lambda v: self.timeout_text.set(f"{float(v):.0f} s")).pack(fill="x")
        ttk.Label(body, textvariable=self.timeout_text, style="CardMuted.TLabel").pack(anchor="w")
        ttk.Button(body, text="Save settings", style="Accent.TButton", command=self.save).pack(fill="x", pady=(12, 4))
        ttk.Button(body, text="Delete face data...", style="Danger.TButton", command=self.delete).pack(fill="x")
        self.msg = ttk.Label(body, style="CardMuted.TLabel", wraplength=260)
        self.msg.pack(anchor="w", pady=(8, 0))

    # -- settings -----------------------------------------------------------------------------
    def refresh(self) -> None:
        enabled, threshold, timeout = dashdata.face_options(self.ctx.db)
        count = dashdata.face_sample_count(self.ctx.db)
        if not count:
            self.samples_info.set("No face enrolled yet")
        elif not enrolment_current(self.ctx.db):  # made by the old YuNet/SFace models
            self.samples_info.set("Face unlock was upgraded: enroll again to use it")
        else:
            self.samples_info.set(f"{count} face sample(s) enrolled")
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
        self.stop()  # release the camera first
        FaceStore(self.ctx.db, self.ctx.keys).clear()
        self.ctx.audit.record("face_cleared")
        self._say("Face data deleted.")
        self.refresh()

    # -- camera sessions ------------------------------------------------------------------------
    def _buttons(self, idle: bool) -> None:
        """Start buttons only while the camera is off, Stop only while it's on."""
        self.enroll_btn.configure(state="normal" if idle else "disabled")
        self.test_btn.configure(state="normal" if idle else "disabled")
        self.stop_btn.configure(state="disabled" if idle else "normal")

    def _begin(self, process, mode: str, seconds: float) -> None:
        """Start the camera thread with `process(frame)` and poll it from the Tk thread."""
        self.mode, self.deadline = mode, time.monotonic() + seconds
        self.matched = False
        self.anim.set_state(face_anim.SCANNING)
        self.session = CameraSession(process)
        self.session.start()
        self._buttons(idle=False)
        self._poll()

    def start_enroll(self) -> None:
        from .enroll import MESSAGES, Enroller
        from .face_store import FaceStore
        try:
            engine = self.app.runtime.engine()  # loads (and hash-checks) the face models once
            samples = int(self.samples_var.get())
        except Exception as exc:
            self._say(f"Face models unavailable: {exc}", True)
            return
        enroller = self.enroller = Enroller(engine, FaceStore(self.ctx.db, self.ctx.keys), samples,
                                            snapshots=self.snap_var.get())

        def process(frame):  # runs on the camera thread: no Tk calls in here
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
        if not enrolment_current(self.ctx.db):
            self._say("Face unlock was upgraded. Enroll your face again first.", True)
            return
        from .liveness import Challenge, random_challenge
        try:
            # Uses the slider's (unsaved) value, so the user can try a strictness before saving it.
            matcher = FaceMatcher(self.app.runtime.engine(), enrolled, round(self.thr_var.get(), 2))
        except Exception as exc:
            self._say(f"Face models unavailable: {exc}", True)
            return
        challenge = Challenge(random_challenge(), matcher.threshold)  # the same test the unlock prompt runs

        def process(frame):  # camera thread: run the full challenge and show the live numbers
            obs = matcher.observe(frame)
            state = challenge.feed(obs)
            numbers = (f"match {obs.identity:.2f} (needs {matcher.threshold:.2f})   real {obs.live:.2f}   "
                       f"yaw {obs.yaw:+.2f}   pitch {obs.pitch:.2f}" if obs.faces == 1
                       else "Need exactly one face in view")
            if state == "matched":
                self.matched = True
                return "Passed: your face matched, looked real, and followed the moves.\n" + numbers, True
            if state == "failed":
                return f"Failed: {challenge.reason}.\n" + numbers, True
            return challenge.instruction + "\n" + numbers, False

        self._say("Test runs the real unlock check: follow the instructions under the camera.")
        self._begin(process, "test", 45)

    def _poll(self) -> None:
        """Every 60 ms on the Tk thread: show the newest frame/status and handle end conditions."""
        session = self.session
        if session is None:
            return
        png = session.frame_if_new()
        if png:
            self._photo = tk.PhotoImage(data=png)  # keep a reference or Tk drops the image
            self.preview.configure(image=self._photo, text="", width=0, height=0)
        self.status_var.set(session.status)
        if session.error:
            self.stop()
            self._say(f"Camera problem: {session.error}", True)
        elif session.done and self.mode == "enroll":
            self._finish_enroll()
        elif session.done:  # test finished: keep its verdict on screen after the camera stops
            verdict, passed = session.status, self.matched
            self.stop()
            self._say(verdict.replace("\n", "  "), not passed)
            self.anim.set_state(face_anim.SUCCESS if passed else face_anim.FAILURE)
        elif time.monotonic() > self.deadline:
            self.stop()
            self._say("Timed out." + (" Nothing was saved." if self.mode == "enroll" else ""), True)
        else:
            self._after = self.after(60, self._poll)

    def _finish_enroll(self) -> None:
        enroller = self.enroller
        self.stop()
        try:
            count = enroller.commit()  # replaces any earlier enrolment in one transaction
        except RuntimeError as exc:
            self._say(str(exc), True)
            return
        self.ctx.audit.record("face_enrolled", f"{count} samples")
        self._say(f"Enrolled {count} samples. They are stored encrypted.")
        self.refresh()
        self.anim.set_state(face_anim.SUCCESS)  # after stop() reset it; play the checkmark

    def stop(self) -> None:
        if self._after is not None:
            self.after_cancel(self._after)
            self._after = None
        if self.session is not None:
            self.session.stop()  # waits for the camera to be released
            self.session = None
        self._photo = None
        self.matched = False
        self.anim.set_state(face_anim.IDLE)
        self.preview.configure(image="", text="Camera off", width=52, height=16)
        self.status_var.set("")
        self._buttons(idle=True)

    def leave(self) -> None:
        self.stop()  # never leave the webcam running on a page nobody is looking at


# --------------------------------------------------------------------------------------------
# Time-range dropdown label -> hours (None = no limit).
RANGES = {"All time": None, "Last hour": 1, "Last 24 hours": 24, "Last 7 days": 24 * 7, "Last 30 days": 24 * 30}


class LogPage(Page):
    title = "Activity log"

    def build(self) -> None:
        # -- filter bar: event type, time range, free text --------------------------------------
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

        # -- severity chips, plus a removable "Day: ..." chip when opened from the chart ----------
        chips = ttk.Frame(self)
        chips.pack(fill="x", pady=(0, 10))
        ttk.Label(chips, text="Show:", style="Muted.TLabel").pack(side="left", padx=(0, 6))
        self.severity, self.day, self.chips = None, None, {}
        for key, text in ((None, "All"), ("good", "Good"), ("warn", "Warnings"), ("bad", "Problems")):
            chip = ttk.Button(chips, text=text, style="Chip.TButton", command=lambda k=key: self.set_severity(k))
            chip.pack(side="left", padx=(0, 4))
            self.chips[key] = chip
        self.day_chip = ttk.Button(chips, style="Chip.TButton", command=lambda: self.set_day(None))
        self._paint_chips()

        outer, body = make_card(self)
        outer.pack(fill="both", expand=True)
        frame, self.tree = make_tree(body, [("time", "Time", 170, False), ("event", "Event", 190, False),
                                            ("detail", "Detail", 420, True)], height=16,
                                     empty="No log entries match these filters.")
        frame.pack(fill="both", expand=True)
        foot = ttk.Frame(self)
        foot.pack(fill="x", pady=(8, 0))
        self.count_var = tk.StringVar()
        ttk.Label(foot, textvariable=self.count_var, style="Muted.TLabel").pack(side="left")
        ttk.Button(foot, text="Reset log chain...", style="Danger.TButton", command=self.reset).pack(side="right")
        ttk.Button(foot, text="Remove old entries", command=self.prune).pack(side="right", padx=6)
        ttk.Button(foot, text="Verify integrity", command=self.verify).pack(side="right")
        self._labels = {}  # friendly label -> raw event id, for the type dropdown

    def refresh(self) -> None:
        types = dashdata.event_types(self.ctx.db)
        self._labels = {dashdata.describe(t): t for t in types}
        self.type_box.configure(values=["All events"] + sorted(self._labels))
        event = self._labels.get(self.type_var.get())
        # A day filter replaces the time range (the day is already a narrower range).
        rows = dashdata.query_events(self.ctx.db, event=event, text=self.search_var.get(),
                                     hours=None if self.day else RANGES[self.range_var.get()], limit=1000,
                                     day=self.day, severity=self.severity)
        fill_events(self.tree, rows)
        self.count_var.set(f"Showing {len(rows)} of {dashdata.count_events(self.ctx.db)} entries (newest first)")

    def _paint_chips(self) -> None:
        for key, chip in self.chips.items():  # highlight the active severity chip
            chip.configure(style="ChipOn.TButton" if key == self.severity else "Chip.TButton")
        if self.day:
            self.day_chip.configure(text=f"Day: {self.day:%a %d %b}  ✕")  # click the chip to clear it
            self.day_chip.pack(side="left", padx=(10, 0))
        else:
            self.day_chip.pack_forget()

    def set_severity(self, severity) -> None:
        self.severity = severity
        self._paint_chips()
        self.refresh()

    def set_day(self, day) -> None:
        self.day = day
        self._paint_chips()
        self.refresh()

    def apply_filter(self, severity=None, range_label=None, day=None) -> None:
        """Jump-in from the Dashboard: replace all filters, then show the matching rows."""
        self.type_var.set("All events")
        self.search_var.set("")
        self.range_var.set(range_label or "Last 7 days")
        self.severity, self.day = severity, day
        self._paint_chips()
        self.refresh()

    def export(self) -> None:
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".csv", initialfile="gatekeeper-log.csv",
                                            filetypes=[("CSV", "*.csv")])
        if path:
            count = self.ctx.audit.export_csv(path)
            messagebox.showinfo("Export", f"Exported {count} entries.", parent=self)

    def verify(self) -> None:
        show_verify_result(self.ctx, self)

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
        # strict: wiping the evidence must always ask, even inside the "remember password" minute.
        if not self.app.confirm_password("reset the log", strict=True):
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
        # -- change password ------------------------------------------------------------------
        outer, body = make_card(self, "Change password")
        outer.pack(fill="x")
        self.cur, self.new, self.rep = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, var in (("Current password", self.cur), ("New password", self.new), ("Repeat new password", self.rep)):
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, style="Card.TLabel", width=20).pack(side="left")
            password_entry(row, var, width=30)[0].pack(side="left")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Change password", style="Accent.TButton", command=self.change_password).pack(side="left")
        self.pw_msg = ttk.Label(row, style="CardMuted.TLabel")
        self.pw_msg.pack(side="left", padx=10)
        ttk.Label(body, style="CardMuted.TLabel", text=f"At least {MIN_PASSWORD_LEN} characters. There is no recovery "
                  "backdoor: if you forget it, see Recovery in docs/USAGE.md.").pack(anchor="w", pady=(6, 0))

        # -- behaviour: auto-lock, retention, theme, password grace -----------------------------
        outer, body = make_card(self, "Behaviour")
        outer.pack(fill="x", pady=(12, 0))
        self.autolock_var, self.retention_var, self.relock_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, var, high, hint in (
                ("Lock this window after", self.autolock_var, 240, "idle minutes (0 = never)"),
                ("Re-lock open apps after", self.relock_var, 240, "idle minutes (0 = only when Windows locks)"),
                ("Keep activity log for", self.retention_var, 3650, "days (0 = forever)")):
            row = ttk.Frame(body, style="Card.TFrame")
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label, style="Card.TLabel", width=22).pack(side="left")
            ttk.Spinbox(row, from_=0, to=high, width=7, textvariable=var).pack(side="left")
            ttk.Label(row, text=" " + hint, style="CardMuted.TLabel").pack(side="left")
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=3)
        ttk.Label(row, text="Theme", style="Card.TLabel", width=22).pack(side="left")
        self.theme_var = tk.StringVar()
        ttk.Combobox(row, textvariable=self.theme_var, values=("Light", "Dark"), state="readonly",
                     width=8).pack(side="left")
        self.grace_var = tk.BooleanVar()
        ttk.Checkbutton(body, variable=self.grace_var, text=(
            f"Remember my password for {dashdata.GRACE_SECONDS} seconds after a confirmation "
            "(quitting and resetting the log always ask)")).pack(anchor="w", pady=(4, 0))
        row = ttk.Frame(body, style="Card.TFrame")
        row.pack(fill="x", pady=(8, 0))
        ttk.Button(row, text="Save", style="Accent.TButton", command=self.save_behaviour).pack(side="left")
        self.beh_msg = ttk.Label(row, style="CardMuted.TLabel")
        self.beh_msg.pack(side="left", padx=10)

        # -- about and recovery ---------------------------------------------------------------
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
        self.relock_var.set(f"{dashdata.relock_minutes(self.ctx.db):g}")
        self.retention_var.set(str(int(self.ctx.db.get_setting("log_retention_days", 90))))
        self.theme_var.set(dashdata.get_theme(self.ctx.db).capitalize())
        self.grace_var.set(dashdata.confirm_grace(self.ctx.db))
        self.about.set(f"Mode: {'DEV (nothing is killed, blocked or locked)' if self.ctx.dev else 'enforcing'}\n"
                       f"Data folder: {self.ctx.directory}")

    def change_password(self) -> None:
        ok, message = dashdata.change_password(self.ctx, self.cur.get(), self.new.get(), self.rep.get())
        self.pw_msg.configure(text=message, foreground=P["good"] if ok else P["bad"])
        if ok:  # don't leave passwords sitting in the fields
            self.cur.set("")
            self.new.set("")
            self.rep.set("")

    def save_behaviour(self) -> None:
        try:
            dashdata.set_autolock_minutes(self.ctx, self.autolock_var.get())
            dashdata.set_relock_minutes(self.ctx, self.relock_var.get())
            dashdata.set_retention_days(self.ctx, self.retention_var.get())
        except ValueError as exc:
            self.beh_msg.configure(text=str(exc), foreground=P["bad"])
            return
        dashdata.set_confirm_grace(self.ctx, self.grace_var.get())
        theme = self.theme_var.get().lower()
        if theme != dashdata.get_theme(self.ctx.db):
            dashdata.set_theme(self.ctx, theme)
            self.app.apply_theme(theme)  # rebuilds the window, so this page is replaced
            return
        self.beh_msg.configure(text="Saved.", foreground=P["good"])

    def open_folder(self) -> None:
        try:
            os.startfile(self.ctx.directory)  # Windows only
        except (AttributeError, OSError):
            messagebox.showinfo("Data folder", str(self.ctx.directory), parent=self)

    def release(self) -> None:
        """Resume locked apps left frozen (e.g. after a crash). Safe here: the dashboard is unlocked."""
        from .guard import release_suspended
        messagebox.showinfo("Released", f"Resumed {release_suspended(self.ctx)} frozen process(es).", parent=self)


# Sidebar order; Ctrl+1..Ctrl+6 follow it too. (key, sidebar label, page class)
PAGES = [("dashboard", "Dashboard", DashboardPage), ("apps", "Locked apps", AppsPage),
         ("usb", "USB and idle lock", UsbIdlePage), ("face", "Face unlock", FacePage),
         ("log", "Activity log", LogPage), ("settings", "Settings", SettingsPage)]
