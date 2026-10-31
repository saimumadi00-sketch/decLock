"""Gatekeeper desktop app: login, sidebar, and the pages in gui_pages.

The guard keeps protecting apps whether or not you are logged in to this window; the password
only gates *managing* Gatekeeper. Closing the window minimizes it (and locks it); quitting
Gatekeeper needs the password.
"""

import logging
import time
import tkinter as tk
from tkinter import messagebox, ttk

from . import auth, dashdata, tray, winapi
from .gui_pages import PAGES
from .gui_widgets import P, apply_style, center, make_card, password_entry
from .idle import IdleLocker
from .runtime import GuardRuntime

log = logging.getLogger("gatekeeper.dashboard")


class Dashboard:
    def __init__(self, ctx, minimized: bool = False, relaunch_args=None, runtime=None, root=None):
        self.ctx, self.minimized = ctx, minimized
        self.relaunch_args = list(relaunch_args or ["gui"])  # how to start an elevated copy of ourselves
        self.root = root or tk.Tk()
        self.root.title("Gatekeeper" + ("  [DEV]" if ctx.dev else ""))
        self.root.minsize(900, 600)
        center(self.root, 1060, 720)
        apply_style(self.root, dashdata.get_theme(ctx.db))
        # The guard (process watcher, USB watcher, idle lock, unlock prompts) lives in this process.
        self.runtime = runtime or GuardRuntime(ctx, self.root)
        self.authed = False                    # is the dashboard unlocked right now?
        self.last_activity = time.monotonic()  # for the dashboard's own idle auto-lock
        self.pages, self.nav, self.current, self._ticks = {}, {}, None, 0
        # _confirmed_until: monotonic time until which a password confirmation is remembered (opt-in).
        self.tray, self._confirmed_until, self.banner = None, 0.0, None
        self._bind_shortcuts()
        for sequence in ("<Key>", "<Button>", "<Motion>"):  # any input counts as activity
            self.root.bind_all(sequence, self._touch, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)  # the X button
        if ctx.dev:
            tk.Label(self.root, bg=P["dev"], fg="#451a03", pady=4,
                     text="DEV MODE: protection is simulated. Nothing is killed, blocked or locked.").pack(fill="x")
        self.stage = ttk.Frame(self.root)  # login card or sidebar + page; rebuilt by _clear()
        self.stage.pack(fill="both", expand=True)

    # -- lifecycle ----------------------------------------------------------------------------
    def run(self) -> None:
        self._start_tray()
        self.start()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()  # always resume frozen apps and stop the threads

    def start(self) -> None:
        if auth.has_password(self.ctx.db):
            self.runtime.start()  # protection starts at once, before anyone logs in
            self._show_login()
        else:
            self._show_setup()    # first run: choose a password (protection starts after that)
        if self.minimized:
            self._hide()
        self.root.after(1000, self._tick)

    def shutdown(self) -> None:
        if self.tray:
            self.tray.stop()
        for page in self.pages.values():
            page.leave()
        self.runtime.stop()

    def quit_app(self) -> None:
        if not messagebox.askyesno("Quit Gatekeeper", "Quit Gatekeeper? Your locked apps will no longer be protected.",
                                   parent=self.root):
            return
        if self.confirm_password("quit Gatekeeper", strict=True):
            self.shutdown()
            self.root.destroy()

    def relaunch_elevated(self) -> None:
        if winapi.relaunch_elevated(self.relaunch_args):
            self.shutdown()  # the new copy waits for our single-instance lock
            self.root.destroy()
        else:
            messagebox.showinfo("Administrator", "The Administrator prompt was cancelled; nothing changed.",
                                parent=self.root)

    def on_close(self) -> None:
        """The X button minimizes and locks the window; protection keeps running."""
        self.lock_ui("window closed")
        self._hide()

    def toggle_protection(self) -> None:
        """Pause (needs the password) or resume protection. Used by the Dashboard page and the tray."""
        if self.runtime.running:
            if not self.confirm_password("pause protection"):
                return
            self.runtime.stop()
        elif auth.has_password(self.ctx.db):
            # Never guard without a password: no prompt could ever succeed, so every locked app
            # that started would be killed.
            self.runtime.start()

    # -- tray ---------------------------------------------------------------------------------
    def _start_tray(self) -> None:
        tray_icon = tray.Tray(lambda: self.runtime.running)
        if tray_icon.start():  # False when pystray/Pillow aren't installed
            self.tray = tray_icon
            self.root.after(200, self._poll_tray)

    def _hide(self) -> None:
        """With a tray icon the window leaves the taskbar; without one it just minimizes."""
        self.root.withdraw() if self.tray else self.root.iconify()

    def show_window(self) -> None:
        self.root.deiconify()
        self.root.state("normal")
        self.root.lift()
        self.root.focus_force()

    def _poll_tray(self) -> None:
        """pystray runs on its own thread, so menu clicks arrive through a queue we drain here."""
        try:
            while self.tray and not self.tray.commands.empty():
                self._tray_command(self.tray.commands.get())
        except Exception:
            log.exception("tray command failed")
        self.root.after(200, self._poll_tray)

    def _tray_command(self, command: str) -> None:
        if command == "open":
            self.show_window()
        elif command == "lock":
            self.lock_ui("tray")
        elif command == "toggle":
            self.show_window()  # the password prompt needs a visible parent
            self.toggle_protection()
            if self.authed and self.current:
                self.pages[self.current].refresh()
        elif command == "quit":
            self.show_window()
            self.quit_app()

    # -- shortcuts and theme --------------------------------------------------------------------
    def _bind_shortcuts(self) -> None:
        # show_page() ignores these while the dashboard is locked, so they can't skip the login.
        self.root.bind_all("<Control-l>", lambda _e: self.lock_ui("shortcut"))
        for number, (key, _label, _cls) in enumerate(PAGES, start=1):
            self.root.bind_all(f"<Control-Key-{number}>", lambda _e, k=key: self.show_page(k))

    def apply_theme(self, theme: str) -> None:
        """Re-skin the whole window. Pages are rebuilt because their colors are set at creation."""
        apply_style(self.root, theme)
        if not self.authed:
            self._show_login() if auth.has_password(self.ctx.db) else self._show_setup()
            return
        current = self.current or "dashboard"
        self._show_main()
        self.show_page(current)

    def open_log(self, severity=None, range_label=None, day=None) -> None:
        """Jump to the Activity log with filters set (used by the Dashboard tiles and chart)."""
        if not self.authed:
            return
        self.show_page("log")
        self.pages["log"].apply_filter(severity, range_label, day)

    def _touch(self, _event=None) -> None:
        self.last_activity = time.monotonic()

    def _tick(self) -> None:
        """Once a second: dashboard auto-lock; every 5 s: tamper banner and auto-refreshing pages."""
        try:
            self._ticks += 1
            if self.authed:
                minutes = dashdata.autolock_minutes(self.ctx.db)
                if minutes > 0 and time.monotonic() - self.last_activity > minutes * 60:
                    self.lock_ui("auto-lock after inactivity")
                elif self._ticks % 5 == 0:
                    self._update_banner()
                    if self.current and self.pages[self.current].auto_refresh:
                        self.pages[self.current].refresh()
        except Exception:
            log.exception("dashboard tick failed")
        self.root.after(1000, self._tick)

    # -- screens ------------------------------------------------------------------------------
    def _clear(self) -> None:
        """Tear down whatever the stage shows (login card or main view)."""
        for page in self.pages.values():
            page.leave()
        for child in self.stage.winfo_children():
            child.destroy()
        self.pages, self.nav, self.current = {}, {}, None

    def _centered_card(self):
        self._clear()
        wrap = ttk.Frame(self.stage)
        wrap.place(relx=0.5, rely=0.45, anchor="center")
        outer, body = make_card(wrap, pad=28)
        outer.pack()
        ttk.Label(body, text="Gatekeeper", style="Big.TLabel").pack(anchor="w")
        return body

    def _show_login(self) -> None:
        self.authed = False
        body = self._centered_card()
        ttk.Label(body, text="Enter your password to open the dashboard.", style="CardMuted.TLabel").pack(anchor="w", pady=(2, 12))
        var = tk.StringVar()
        row, entry = password_entry(body, var)
        row.pack(fill="x")
        message = ttk.Label(body, style="Err.TLabel", wraplength=300)
        message.pack(anchor="w", pady=(8, 0))
        watching = {"on": False}  # a countdown is already running; don't start a second one

        def watch_lockout() -> None:
            """Show the lockout message and count it down live until it ends."""
            if watching["on"] or not message.winfo_exists():
                return
            watching["on"] = True

            def tick() -> None:
                if not message.winfo_exists():  # login screen was replaced meanwhile
                    return
                wait = auth.lockout_remaining(self.ctx.db)
                if wait > 0:
                    message.configure(text=f"Too many wrong passwords. Try again in {int(wait) + 1}s.")
                    message.after(250, tick)
                else:
                    watching["on"] = False
                    message.configure(text="")

            tick()

        def submit(_event=None) -> None:
            password = var.get()
            var.set("")  # never leave the password in the field
            wait = auth.lockout_remaining(self.ctx.db)
            if wait > 0:
                watch_lockout()
            elif auth.check_password(self.ctx.db, password, self.ctx.audit):
                self._login_ok()
            else:
                self.ctx.audit.record("bad_password", "dashboard")
                if auth.lockout_remaining(self.ctx.db) > 0:  # this failure started a lockout
                    watch_lockout()
                else:
                    message.configure(text="Wrong password.")

        entry.bind("<Return>", submit)
        ttk.Button(body, text="Open dashboard", style="Accent.TButton", command=submit).pack(fill="x", pady=(10, 0))
        entry.focus_set()
        watch_lockout()  # already locked out from earlier attempts? show it straight away
        self.login_submit, self.login_var = submit, var  # exposed for tests

    def _show_setup(self) -> None:
        self.authed = False
        body = self._centered_card()
        ttk.Label(body, text=f"Welcome. Choose a password (at least {auth.MIN_PASSWORD_LEN} characters).\n"
                  "It protects this dashboard and unlocks your locked apps.",
                  style="CardMuted.TLabel", justify="left").pack(anchor="w", pady=(2, 12))
        first, second = tk.StringVar(), tk.StringVar()
        password_entry(body, first)[0].pack(fill="x")
        password_entry(body, second)[0].pack(fill="x", pady=(6, 0))
        message = ttk.Label(body, style="Err.TLabel", wraplength=300)
        message.pack(anchor="w", pady=(8, 0))

        def submit(_event=None) -> None:
            ok, error = dashdata.create_password(self.ctx, first.get(), second.get())
            if not ok:
                message.configure(text=error)
                return
            self.runtime.start()
            self._login_ok()

        ttk.Button(body, text="Create password", style="Accent.TButton", command=submit).pack(fill="x", pady=(10, 0))
        self.setup_submit, self.setup_vars = submit, (first, second)

    def _login_ok(self) -> None:
        self.authed = True
        self._touch()
        self.ctx.audit.record("dashboard_login")
        self._show_main()

    def lock_ui(self, reason: str = "") -> None:
        if not self.authed:
            return
        self.ctx.audit.record("dashboard_locked", reason)
        self._confirmed_until = 0.0  # a remembered confirmation never survives a lock
        self._show_login()

    def _show_main(self) -> None:
        """Sidebar on the left; tamper banner + the current page on the right."""
        self._clear()
        side = ttk.Frame(self.stage, style="Side.TFrame", width=214)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)  # keep the fixed width
        ttk.Label(side, text="Gatekeeper", style="Brand.TLabel", padding=(18, 22, 18, 0)).pack(anchor="w")
        ttk.Label(side, text="App lock for Windows", style="SideMuted.TLabel", padding=(18, 0, 18, 18)).pack(anchor="w")
        for key, label, _cls in PAGES:
            button = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show_page(k))
            button.pack(fill="x")
            self.nav[key] = button
        ttk.Button(side, text="Quit Gatekeeper", style="Nav.TButton", command=self.quit_app).pack(side="bottom", fill="x", pady=(0, 10))
        ttk.Button(side, text="Lock dashboard", style="Nav.TButton", command=lambda: self.lock_ui("manual")).pack(side="bottom", fill="x")
        right = ttk.Frame(self.stage)
        right.pack(side="right", fill="both", expand=True)
        self.banner = ttk.Label(right, style="Banner.TLabel", anchor="w")  # packed only when needed
        self.content = ttk.Frame(right)
        self.content.pack(fill="both", expand=True)
        self.show_page("dashboard")

    def show_page(self, key: str) -> None:
        if not self.authed:  # also guards the Ctrl+number shortcuts while locked
            return
        if self.current and self.current != key:
            self.pages[self.current].pack_forget()
            self.pages[self.current].leave()
        if key not in self.pages:  # pages are built lazily, on first visit
            cls = next(c for k, _l, c in PAGES if k == key)
            self.pages[key] = cls(self.content, self)
        self.pages[key].pack(fill="both", expand=True)
        self.pages[key].refresh()
        self.current = key
        self._update_banner()
        for k, button in self.nav.items():
            button.configure(style="NavActive.TButton" if k == key else "Nav.TButton")

    def _update_banner(self) -> None:
        """A red strip on every page while the audit log fails its integrity check."""
        if self.banner is None or not self.banner.winfo_exists():
            return
        ok, bad = self.ctx.audit.verify()  # incremental: only new rows are hashed
        if ok:
            self.banner.pack_forget()
        else:
            self.banner.configure(text=f"Audit log tampering detected at entry {bad}. "
                                       "Export the log from Activity log, then investigate.")
            self.banner.pack(fill="x", before=self.content)

    # -- helpers used by pages ----------------------------------------------------------------
    def lock_windows(self) -> None:
        locked = IdleLocker(self.ctx, 0).lock("manual_lock", "dashboard")
        if self.ctx.dev:
            messagebox.showinfo("Dev mode", "Dev mode: the Windows lock was simulated and logged.", parent=self.root)
        elif not locked:
            messagebox.showwarning("Lock", "Windows could not be locked.", parent=self.root)

    def confirm_password(self, action: str, strict: bool = False) -> bool:
        """Modal password check for risky actions. Shares the normal lockout and audit rules.
        If the user opted in (Settings), a success is remembered for a minute; `strict` actions
        such as quitting always ask."""
        db, audit = self.ctx.db, self.ctx.audit
        grace = dashdata.confirm_grace(db)
        if not strict and grace and time.monotonic() < self._confirmed_until:
            return True
        wait = auth.lockout_remaining(db)
        if wait > 0:
            messagebox.showwarning("Locked out", f"Too many wrong passwords. Try again in {int(wait) + 1}s.",
                                   parent=self.root)
            return False
        result = {"ok": False}
        win = tk.Toplevel(self.root)
        win.title("Confirm")
        win.transient(self.root)
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.configure(bg=P["bg"])
        frame = ttk.Frame(win, padding=18)
        frame.pack()
        ttk.Label(frame, text=f"Enter your password to {action}.").pack(anchor="w")
        var = tk.StringVar()
        row_entry, entry = password_entry(frame, var, width=32)
        row_entry.pack(fill="x", pady=8)
        message = ttk.Label(frame, foreground=P["bad"])
        message.pack(anchor="w")
        tries = {"left": 3}  # the dialog closes after 3 misses (the global lockout still applies)

        def submit(_event=None) -> None:
            password = var.get()
            var.set("")
            if auth.check_password(db, password, audit):
                result["ok"] = True
                if grace:  # only start the "remember" window when the user asked for it
                    self._confirmed_until = time.monotonic() + dashdata.GRACE_SECONDS
                win.destroy()
                return
            audit.record("bad_password", f"dashboard: {action}")
            tries["left"] -= 1
            if tries["left"] <= 0 or auth.lockout_remaining(db) > 0:
                win.destroy()
            else:
                message.configure(text=f"Wrong password. {tries['left']} attempt(s) left.")

        entry.bind("<Return>", submit)
        row = ttk.Frame(frame)
        row.pack(anchor="e", pady=(8, 0))
        ttk.Button(row, text="Cancel", command=win.destroy).pack(side="right")
        ttk.Button(row, text="Confirm", style="Accent.TButton", command=submit).pack(side="right", padx=6)
        # Centre the dialog over the main window.
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_reqheight()) // 3
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.grab_set()           # modal: the rest of the app ignores input until it closes
        entry.focus_force()
        self.root.wait_window(win)  # block here (events still run) until the dialog is gone
        return result["ok"]


def run_dashboard(ctx, minimized: bool = False, relaunch_args=None) -> None:
    winapi.enable_dpi_awareness()
    Dashboard(ctx, minimized, relaunch_args).run()
