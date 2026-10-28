"""Process guard: suspend newly started locked apps until the password is entered.

Flow per locked process: detect -> suspend -> ask UI for password -> resume
(and grant that app name a time window) or kill the process tree.

Windows cannot reliably stop a process from *starting* without kernel-level
help, so this is detect-and-suspend: there is a window of a few hundred
milliseconds before the first scan sees the process.
"""

import logging
import threading
import time
from typing import Callable

import psutil

log = logging.getLogger("gatekeeper.guard")


class Guard:
    def __init__(self, ctx, on_locked: Callable[[str], None], poll: float = 0.5, grant_seconds: float = 600):
        self.ctx = ctx
        self.on_locked = on_locked
        self.poll = poll
        self.grant_seconds = grant_seconds
        self._seen = set()
        self._pending = {}   # app name -> [psutil.Process]
        self._granted = {}   # app name -> monotonic expiry
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None

    # -- scanning -----------------------------------------------------------
    def scan(self) -> None:
        locked = set(self.ctx.db.list_apps())
        alive = set()
        for proc in psutil.process_iter(["name", "create_time"]):
            try:
                key = (proc.pid, proc.info["create_time"])
                alive.add(key)
                name = (proc.info["name"] or "").lower()
                if name in locked and key not in self._seen:
                    self._seen.add(key)
                    self._handle(name, proc)
            except psutil.Error:
                continue
        self._seen &= alive

    def _handle(self, name: str, proc: psutil.Process) -> None:
        with self._lock:
            if self._granted.get(name, 0) > time.monotonic():
                log.debug("%s pid %d allowed by active grant", name, proc.pid)
                return
            if self.ctx.dev:
                log.info("[DEV] would suspend and prompt for %s (pid %d); no action taken", name, proc.pid)
                return
            try:
                proc.suspend()
            except psutil.Error as exc:
                self.ctx.audit.record("enforce_failed", f"{name} pid={proc.pid} cannot suspend: {exc}")
                return
            queue = self._pending.setdefault(name, [])
            first = not queue
            queue.append(proc)
        self.ctx.audit.record("blocked", f"{name} pid={proc.pid}")
        if first:
            self.on_locked(name)

    # -- decisions ----------------------------------------------------------
    def resolve(self, name: str, allowed: bool) -> None:
        with self._lock:
            procs = self._pending.pop(name, [])
            if allowed:
                self._granted[name] = time.monotonic() + self.grant_seconds
        for proc in procs:
            try:
                if allowed:
                    proc.resume()
                else:
                    self._kill_tree(proc)
            except psutil.Error as exc:
                log.warning("could not %s pid %d: %s", "resume" if allowed else "kill", proc.pid, exc)
        self.ctx.audit.record("unlocked" if allowed else "denied", f"{name} ({len(procs)} process(es))")

    @staticmethod
    def _kill_tree(proc: psutil.Process) -> None:
        victims = proc.children(recursive=True) + [proc]
        for p in victims:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(victims, timeout=3)

    def release_all(self) -> None:
        """Fail open on shutdown: never leave processes frozen."""
        with self._lock:
            procs = [p for group in self._pending.values() for p in group]
            self._pending.clear()
        for proc in procs:
            try:
                proc.resume()
            except psutil.Error:
                pass
        if procs:
            self.ctx.audit.record("released_on_exit", f"{len(procs)} process(es)")

    # -- thread -------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="guard", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception:
                log.exception("scan failed")
            self._stop.wait(self.poll)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self.release_all()


def release_suspended(ctx) -> int:
    """Recovery: resume any locked-app process left frozen (e.g. the guard was force-killed
    while a password prompt was open). Needs no password; it can only un-freeze."""
    locked = set(ctx.db.list_apps())
    resumed = 0
    for proc in psutil.process_iter(["name", "status"]):
        try:
            if (proc.info["name"] or "").lower() in locked and proc.info["status"] == psutil.STATUS_STOPPED:
                proc.resume()
                resumed += 1
        except psutil.Error:
            continue
    if resumed:
        ctx.audit.record("released_manually", f"{resumed} process(es)")
    return resumed
