"""The running guard (process watcher, USB watcher, idle lock, unlock prompts) as one object.

Shared by the headless `run` command and the desktop dashboard, so both behave identically.
The unlock prompts are Toplevels of `root`, so `root` may be hidden (headless) or be the
dashboard window.
"""

import logging
import queue

from . import auth
from .guard import Guard
from .idle import IdleLocker
from .matcher import build_face_unlock
from .usb import UsbPolicy, UsbWatcher

log = logging.getLogger("gatekeeper.runtime")


class GuardRuntime:
    def __init__(self, ctx, root):
        self.ctx, self.root = ctx, root
        self.running = False
        self.guard = self.usb_watcher = self.idle_locker = None
        self._events: "queue.Queue[str]" = queue.Queue()
        self._busy = False
        self._engine = None
        self._after = None

    # -- face engine (models load once, on first use) -----------------------------------------
    def engine(self):
        if self._engine is None:
            from .faces import FaceEngine
            self._engine = FaceEngine()
        return self._engine

    # -- lifecycle ----------------------------------------------------------------------------
    def start(self) -> None:
        if self.running:
            return
        from .app import startup_checks
        startup_checks(self.ctx, self.root)
        self.ctx.audit.record("guard_start", "dev" if self.ctx.dev else "enforcing")
        log.info("Guard running (%s).", "DEV: log only" if self.ctx.dev else "enforcing")
        self.guard = Guard(self.ctx, self._events.put)
        self.guard.start()
        self.usb_watcher = UsbWatcher(self.ctx, UsbPolicy(self.ctx))
        self.usb_watcher.start()
        self.running = True
        self.apply_idle_setting()
        self._pump()

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        if self._after is not None:
            try:
                self.root.after_cancel(self._after)
            except Exception:
                pass
            self._after = None
        if self.idle_locker:
            self.idle_locker.stop()
            self.idle_locker = None
        self.usb_watcher.stop()
        self.guard.stop()  # also resumes anything still frozen
        self.ctx.audit.record("guard_stop")

    def apply_idle_setting(self) -> None:
        """(Re)start the idle locker from the saved setting; call after it changes."""
        if self.idle_locker:
            self.idle_locker.stop()
            self.idle_locker = None
        minutes = float(self.ctx.db.get_setting("idle_lock_minutes", 0))
        if self.running and minutes > 0:
            self.idle_locker = IdleLocker(self.ctx, minutes)
            self.idle_locker.start()

    # -- unlock prompts -----------------------------------------------------------------------
    def _pump(self) -> None:
        if not self.running:
            return
        self._show_next()
        self._after = self.root.after(200, self._pump)

    def _show_next(self) -> None:
        if self._busy or self._events.empty():
            return
        from .ui import UnlockPrompt
        name = self._events.get()
        self._busy = True
        ctx = self.ctx

        def done(allowed: bool) -> None:
            self._busy = False
            self.guard.resolve(name, allowed)

        def face_result(face_state: str, score) -> None:
            shown = "n/a" if score is None else f"{score:.2f}"
            ctx.audit.record({"matched": "face_unlock", "failed": "face_failed"}.get(face_state, "face_unavailable"),
                             f"{name} best_score={shown}")

        UnlockPrompt(
            self.root, name, lambda pw: auth.check_password(ctx.db, pw, ctx.audit), done,
            on_failure=lambda: ctx.audit.record("bad_password", name),
            lockout=lambda: auth.lockout_remaining(ctx.db),
            face=build_face_unlock(ctx, self.engine), on_face_result=face_result)
