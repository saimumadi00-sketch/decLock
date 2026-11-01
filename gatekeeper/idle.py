"""Idle auto-lock. Uses the real Windows lock screen; a custom overlay cannot be made
secure (Ctrl+Alt+Del, Task Manager and Win+L stay reachable behind it)."""

import logging
import threading

from . import winapi

log = logging.getLogger("gatekeeper.idle")


class IdleLocker:
    def __init__(self, ctx, minutes: float, idle_fn=winapi.idle_seconds,
                 lock_fn=winapi.lock_workstation, poll: float = 5):
        self.ctx, self.minutes, self.poll = ctx, minutes, poll
        self.idle_fn, self.lock_fn = idle_fn, lock_fn
        self._fired = False
        self._stop = threading.Event()
        self._thread = None

    def tick(self) -> None:
        """One check: lock if the user has been idle long enough."""
        if self.idle_fn() < self.minutes * 60:
            self._fired = False
            return
        if self._fired:
            return
        self._fired = True  # one lock per idle period, so unlocking isn't immediately re-locked
        self.lock("idle_lock", f"idle >= {self.minutes} min")

    def lock(self, event: str, detail: str) -> bool:
        """Lock Windows now (simulated in dev mode) and log it. True if it locked."""
        if self.ctx.dev:
            log.info("[DEV] would lock the workstation (%s); no action taken", detail)
            self.ctx.audit.record(event + "_dev", detail)
            return False
        ok = self.lock_fn()
        self.ctx.audit.record(event if ok else event + "_failed", detail)
        return ok

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="idle", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("idle tick failed")
            self._stop.wait(self.poll)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)


RELOCK_KEY = "relock_minutes"
DEFAULT_RELOCK = 10.0  # minutes without input before open locked apps lock again (0 = only on Windows lock)
PRESENT_SECONDS = 5    # input this recent means someone is at the PC (used to re-ask for held apps)
REASK_SECONDS = 15     # after a held app's prompt is refused or ignored, wait this long before asking again


def relock_minutes(db) -> float:
    return float(db.get_setting(RELOCK_KEY, DEFAULT_RELOCK))


class Relocker:
    """Decides when apps that are already open must be locked again, like a phone's app lock
    after the screen turns off: when Windows locks, and after `relock_minutes` without input.

    Tk-free and polled from the Tk thread (GuardRuntime) once a second."""

    def __init__(self, guard, minutes_fn, idle_fn=winapi.idle_seconds, locked_fn=winapi.session_locked,
                 clock=None):
        import time
        self.guard, self.minutes_fn = guard, minutes_fn
        self.idle_fn, self.locked_fn = idle_fn, locked_fn
        self.clock = clock or time.monotonic
        self._was_locked = False
        self._idle_fired = False
        self._next_ask = 0.0

    def tick(self) -> None:
        try:
            locked, idle = self.locked_fn(), self.idle_fn()
        except OSError:
            return
        if locked and not self._was_locked:
            self.guard.relock("Windows locked")
        self._was_locked = locked
        minutes = self.minutes_fn()
        if minutes > 0 and idle >= minutes * 60:
            if not self._idle_fired:
                self._idle_fired = True  # once per idle stretch
                self.guard.relock(f"idle >= {minutes:g} min")
        else:
            self._idle_fired = False

    def present(self) -> bool:
        """Someone is using the desktop right now (not locked, recent input)."""
        try:
            return not self.locked_fn() and self.idle_fn() < PRESENT_SECONDS
        except OSError:
            return False

    def may_ask(self) -> bool:
        """Re-ask for held apps only when someone is here, and not straight after a refusal."""
        return self.present() and self.clock() >= self._next_ask

    def asked(self) -> None:
        self._next_ask = self.clock() + REASK_SECONDS
