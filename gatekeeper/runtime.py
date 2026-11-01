"""The running guard (process watcher, USB watcher, idle lock, unlock prompts) as one object.

Shared by the headless `run` command and the desktop dashboard, so both behave identically.
The unlock prompts are Toplevels of `root`, so `root` may be hidden (headless) or be the
dashboard window.
"""

import logging
import queue
import threading

from . import auth
from .folders import FolderLocker
from .guard import Guard
from .idle import IdleLocker, Relocker, relock_minutes
from .matcher import build_face_unlock
from .usb import UsbPolicy, UsbWatcher

log = logging.getLogger("gatekeeper.runtime")


class GuardRuntime:
    def __init__(self, ctx, root):
        self.ctx, self.root = ctx, root
        self.running = False
        self.guard = self.usb_watcher = self.idle_locker = None
        # The guard thread puts app names here; the Tk thread takes them off and shows prompts.
        self._events: "queue.Queue[str]" = queue.Queue()
        self._busy = False   # a prompt is open (one at a time)
        self._engine = None  # FaceEngine, loaded on first use
        self._after = None   # the pending _pump timer
        self.relocker = None  # locks open apps again when Windows locks or the user is idle
        self.folders = FolderLocker(ctx)
        self._folder_job = None  # background thread running icacls (re-lock / repair)
        self._ticks = 0
        self._session_locked = False

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
        self.relocker = Relocker(self, lambda: relock_minutes(self.ctx.db))  # calls self.relock()
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
        """Every 200 ms on the Tk thread: open the next queued prompt, if none is open."""
        if not self.running:
            return
        self._ticks += 1
        if self._ticks % 5 == 0:  # once a second
            self._relock_tick()
        if self._ticks % 150 == 0:  # every 30 seconds: put back folder locks removed behind our back
            self._folder_background(self.folders.enforce)
            witness = getattr(self.ctx.audit, "witness", None)
            if witness is not None:
                witness.checkpoint(self.ctx.db)  # at most hourly; cheap otherwise
        self._show_next()
        self._after = self.root.after(200, self._pump)

    def relock(self, reason: str) -> None:
        """Windows locked or the PC went idle: lock open apps and unlocked folders again."""
        self.guard.relock(reason)
        self._folder_background(lambda: self.folders.relock_all(reason))

    def _folder_background(self, job) -> None:
        """Run a folder job (icacls can take a while) off the Tk thread, one at a time."""
        if self._folder_job is not None and self._folder_job.is_alive():
            return

        def run():
            try:
                job()
            except Exception:
                log.exception("folder job failed")
        self._folder_job = threading.Thread(target=run, name="folders", daemon=True)
        self._folder_job.start()

    def _relock_tick(self) -> None:
        """Re-lock open apps when needed, and re-ask for held ones once someone is back."""
        try:
            self._session_locked = self.relocker.locked_fn()
            self.relocker.tick()
            if not self._busy and self._events.empty() and self.guard.held() and self.relocker.may_ask():
                self.relocker.asked()
                self.guard.reprompt_held()
        except Exception:  # e.g. no Windows APIs (tests on other systems): re-locking just stays off
            log.debug("relock tick failed", exc_info=True)

    def _show_next(self) -> None:
        if self._busy or self._events.empty() or self._session_locked:
            return  # while Windows is locked nobody could answer, so prompts wait for the user
        from .ui import UnlockPrompt
        name = self._events.get()
        self._busy = True
        ctx = self.ctx

        def done(allowed: bool) -> None:  # the prompt finished: resume, kill, or (re-locked apps) keep holding
            self._busy = False
            if not allowed and self.relocker:
                self.relocker.asked()  # don't re-ask for a held app straight away
            self.guard.resolve(name, allowed)

        def face_result(face_state: str, score) -> None:  # log every face attempt with its best score
            shown = "n/a" if score is None else f"{score:.2f}"
            if face_state == "failed" and score is not None:  # a face was seen and not accepted
                auth.face_failed(ctx.db, ctx.audit)
            why = getattr(face, "reason", "") if face_state == "failed" else ""
            ctx.audit.record({"matched": "face_unlock", "failed": "face_failed"}.get(face_state, "face_unavailable"),
                             f"{name} best_score={shown}" + (f" ({why})" if why else ""))

        face = build_face_unlock(ctx, self.engine)  # None when face unlock is off or not enrolled
        UnlockPrompt(
            self.root, name, lambda pw: auth.check_password(ctx.db, pw, ctx.audit), done,
            on_failure=lambda: ctx.audit.record("bad_password", name),
            lockout=lambda: auth.lockout_remaining(ctx.db),
            face=face, on_face_result=face_result)
