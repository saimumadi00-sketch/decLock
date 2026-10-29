"""Gatekeeper desktop app: login, sidebar, and the pages in gui_pages.

The guard keeps protecting apps whether or not you are logged in to this window; the password
only gates *managing* Gatekeeper. Closing the window minimizes it (and locks it); quitting
Gatekeeper needs the password.
"""

import logging
import time
import tkinter as tk
from tkinter import messagebox, ttk

from . import auth, dashdata, winapi
from .gui_pages import PAGES
from .gui_widgets import P, apply_style, center, make_card
from .idle import IdleLocker
from .runtime import GuardRuntime

log = logging.getLogger("gatekeeper.dashboard")


class Dashboard:
    def __init__(self, ctx, minimized: bool = False, relaunch_args=None, runtime=None, root=None):
        self.ctx, self.minimized = ctx, minimized
        self.relaunch_args = list(relaunch_args or ["gui"])
        self.root = root or tk.Tk()
        self.root.title("Gatekeeper" + ("  [DEV]" if ctx.dev else ""))
        self.root.minsize(900, 600)
        center(self.root, 1060, 720)
        apply_style(self.root)
        self.runtime = runtime or GuardRuntime(ctx, self.root)
        self.authed = False
        self.last_activity = time.monotonic()
        self.pages, self.nav, self.current, self._ticks = {}, {}, None, 0
        for sequence in ("<Key>", "<Button>", "<Motion>"):
            self.root.bind_all(sequence, self._touch, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        if ctx.dev:
            tk.Label(self.root, bg=P["dev"], fg="#451a03", pady=4,
                     text="DEV MODE: protection is simulated. Nothing is killed, blocked or locked.").pack(fill="x")
        self.stage = ttk.Frame(self.root)
        self.stage.pack(fill="both", expand=True)

    # -- lifecycle ----------------------------------------------------------------------------
    def run(self) -> None:
        self.start()
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown()

    def start(self) -> None:
        if auth.has_password(self.ctx.db):
            self.runtime.start()
            self._show_login()
        else:
            self._show_setup()
        if self.minimized:
            self.root.iconify()
        self.root.after(1000, self._tick)

    def shutdown(self) -> None:
        for page in self.pages.values():
            page.leave()
        self.runtime.stop()

    def quit_app(self) -> None:
        if not messagebox.askyesno("Quit Gatekeeper", "Quit Gatekeeper? Your locked apps will no longer be protected.",
                                   parent=self.root):
            return
        if self.confirm_password("quit Gatekeeper"):
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
        self.root.iconify()

    def _touch(self, _event=None) -> None:
        self.last_activity = time.monotonic()

    def _tick(self) -> None:
        try:
            self._ticks += 1
            if self.authed:
                minutes = dashdata.autolock_minutes(self.ctx.db)
                if minutes > 0 and time.monotonic() - self.last_activity > minutes * 60:
                    self.lock_ui("auto-lock after inactivity")
                elif self._ticks % 5 == 0 and self.current and self.pages[self.current].auto_refresh:
                    self.pages[self.current].refresh()
        except Exception:
            log.exception("dashboard tick failed")
        self.root.after(1000, self._tick)

    # -- screens ------------------------------------------------------------------------------
    def _clear(self) -> None:
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
        entry = ttk.Entry(body, textvariable=var, show="*", width=34)
        entry.pack(fill="x")
        message = ttk.Label(body, style="Err.TLabel", wraplength=300)
        message.pack(anchor="w", pady=(8, 0))

        def submit(_event=None) -> None:
            password = var.get()
            var.set("")
            wait = auth.lockout_remaining(self.ctx.db)
            if wait > 0:
                message.configure(text=f"Too many wrong passwords. Try again in {int(wait) + 1}s.")
            elif auth.check_password(self.ctx.db, password, self.ctx.audit):
                self._login_ok()
            else:
                self.ctx.audit.record("bad_password", "dashboard")
                wait = auth.lockout_remaining(self.ctx.db)
                message.configure(text="Wrong password." if wait <= 0 else
                                  f"Too many wrong passwords. Try again in {int(wait) + 1}s.")

        entry.bind("<Return>", submit)
        ttk.Button(body, text="Open dashboard", style="Accent.TButton", command=submit).pack(fill="x", pady=(10, 0))
        entry.focus_set()
        self.login_submit, self.login_var = submit, var  # exposed for tests

    def _show_setup(self) -> None:
        self.authed = False
        body = self._centered_card()
        ttk.Label(body, text=f"Welcome. Choose a password (at least {auth.MIN_PASSWORD_LEN} characters).\n"
                  "It protects this dashboard and unlocks your locked apps.",
                  style="CardMuted.TLabel", justify="left").pack(anchor="w", pady=(2, 12))
        first, second = tk.StringVar(), tk.StringVar()
        ttk.Entry(body, textvariable=first, show="*", width=34).pack(fill="x")
        ttk.Entry(body, textvariable=second, show="*", width=34).pack(fill="x", pady=(6, 0))
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
        self._show_login()

    def _show_main(self) -> None:
        self._clear()
        side = ttk.Frame(self.stage, style="Side.TFrame", width=214)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        ttk.Label(side, text="Gatekeeper", style="Brand.TLabel", padding=(18, 22, 18, 0)).pack(anchor="w")
        ttk.Label(side, text="App lock for Windows", style="SideMuted.TLabel", padding=(18, 0, 18, 18)).pack(anchor="w")
        for key, label, _cls in PAGES:
            button = ttk.Button(side, text=label, style="Nav.TButton", command=lambda k=key: self.show_page(k))
            button.pack(fill="x")
            self.nav[key] = button
        ttk.Button(side, text="Quit Gatekeeper", style="Nav.TButton", command=self.quit_app).pack(side="bottom", fill="x", pady=(0, 10))
        ttk.Button(side, text="Lock dashboard", style="Nav.TButton", command=lambda: self.lock_ui("manual")).pack(side="bottom", fill="x")
        self.content = ttk.Frame(self.stage)
        self.content.pack(side="right", fill="both", expand=True)
        self.show_page("dashboard")

    def show_page(self, key: str) -> None:
        if not self.authed:
            return
        if self.current and self.current != key:
            self.pages[self.current].pack_forget()
            self.pages[self.current].leave()
        if key not in self.pages:
            cls = next(c for k, _l, c in PAGES if k == key)
            self.pages[key] = cls(self.content, self)
        self.pages[key].pack(fill="both", expand=True)
        self.pages[key].refresh()
        self.current = key
        for k, button in self.nav.items():
            button.configure(style="NavActive.TButton" if k == key else "Nav.TButton")

    # -- helpers used by pages ----------------------------------------------------------------
    def lock_windows(self) -> None:
        locked = IdleLocker(self.ctx, 0).lock("manual_lock", "dashboard")
        if self.ctx.dev:
            messagebox.showinfo("Dev mode", "Dev mode: the Windows lock was simulated and logged.", parent=self.root)
        elif not locked:
            messagebox.showwarning("Lock", "Windows could not be locked.", parent=self.root)

    def confirm_password(self, action: str) -> bool:
        """Modal password check for risky actions. Shares the normal lockout and audit rules."""
        db, audit = self.ctx.db, self.ctx.audit
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
        frame = ttk.Frame(win, padding=18)
        frame.pack()
        ttk.Label(frame, text=f"Enter your password to {action}.").pack(anchor="w")
        var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=var, show="*", width=32)
        entry.pack(fill="x", pady=8)
        message = ttk.Label(frame, foreground=P["bad"])
        message.pack(anchor="w")
        tries = {"left": 3}

        def submit(_event=None) -> None:
            password = var.get()
            var.set("")
            if auth.check_password(db, password, audit):
                result["ok"] = True
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
        win.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_reqwidth()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_reqheight()) // 3
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.grab_set()
        entry.focus_force()
        self.root.wait_window(win)
        return result["ok"]


def run_dashboard(ctx, minimized: bool = False, relaunch_args=None) -> None:
    winapi.enable_dpi_awareness()
    Dashboard(ctx, minimized, relaunch_args).run()
