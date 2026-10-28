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
        if self.idle_fn() < self.minutes * 60:
            self._fired = False
            return
        if self._fired:
            return
        self._fired = True  # one lock per idle period, so unlocking isn't immediately re-locked
        self.lock("idle_lock", f"idle >= {self.minutes} min")

    def lock(self, event: str, detail: str) -> bool:
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
