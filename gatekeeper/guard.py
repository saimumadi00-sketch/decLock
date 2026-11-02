"""Process guard: suspend newly started locked apps until the password is entered.

Flow per locked process: detect -> suspend -> ask UI for password -> resume
(and grant that app name a time window) or kill the process tree.

Windows cannot reliably stop a process from *starting* without kernel-level
help, so this is detect-and-suspend: there is a window of a few hundred
milliseconds before the first scan sees the process.

A process counts as a locked app if its name is locked, or if its program file really is a
locked app that was renamed or copied (see identity.py).
"""

import logging
import threading
import time
from typing import Callable

import psutil

from . import schedule
from .identity import Identifier

log = logging.getLogger("gatekeeper.guard")


class Guard:
    def __init__(self, ctx, on_locked: Callable[[str], None], poll: float = 0.5, grant_seconds: float = 600):
        self.ctx = ctx
        self.on_locked = on_locked          # called (from the guard thread) with the app name to prompt for
        self.poll = poll                    # seconds between process scans
        self.grant_seconds = grant_seconds  # after an unlock, new copies of that app start freely this long
        self._seen = set()  # (pid, create_time) already handled; create_time stops PID reuse fooling us
        self._names = {}    # (pid, create_time) -> the locked app it really is (or None), worked out once
        self._apps = None   # the locked-app list _names was computed against
        self.identity = Identifier(ctx.db)
        self._pending = {}   # app name -> [psutil.Process]
        self._granted = {}   # app name -> monotonic expiry
        # Re-locking apps that were already open (Windows locked, or idle). Those processes may hold
        # unsaved work, so they are frozen and HELD: a wrong or cancelled prompt never kills them.
        self._relock_requested = False  # set by relock(), taken by the start of the next scan
        self._relocking = False         # the scan in progress is a re-lock pass
        self._soft = set()       # app names whose waiting processes are held, never killed
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None

    # -- scanning -----------------------------------------------------------
    def scan(self) -> None:
        """One pass over all processes: suspend each new instance of a currently-locked app."""
        apps = frozenset(self.ctx.db.list_apps())
        if apps != self._apps:  # an app was locked or unlocked: re-check every process against the new list
            self._apps, self._names = apps, {}
        locked = schedule.locked_now(self.ctx.db)  # apps whose lock schedule is active right now
        with self._lock:  # a re-lock applies to one WHOLE pass, so start it here, never mid-pass
            self._relocking, self._relock_requested = self._relock_requested, False
            if self._relocking:
                waiting = {self._key(p) for group in self._pending.values() for p in group}
                self._seen = {k for k in self._seen if k in waiting}  # never suspend a frozen process twice
        alive, by_file = set(), []
        for proc in psutil.process_iter(["name", "create_time"]):
            try:
                key = (proc.pid, proc.info["create_time"])
                alive.add(key)
                real = (proc.info["name"] or "").lower()
                if real in apps:
                    self._check(key, real, proc, locked)  # name match: cheap, so handle it first
                else:
                    by_file.append((key, real, proc))
            except psutil.Error:
                continue
        # Second pass: the rest may need their program file read and hashed (cached after the first time),
        # so a slow file never delays freezing an app whose name is locked.
        for key, real, proc in by_file:
            try:
                self._check(key, real, proc, locked)
            except psutil.Error:
                continue
        self._relocking = False  # a re-lock lasts exactly one full pass
        self._seen &= alive  # forget processes that have exited
        self._names = {k: v for k, v in self._names.items() if k in alive}

    def _check(self, key, real: str, proc: psutil.Process, locked) -> None:
        """Freeze `proc` if it is (a copy of) a locked app we haven't handled yet."""
        app = self._resolve(key, real, proc)
        if app in locked and key not in self._seen:
            self._seen.add(key)
            self._handle(app, proc, real)

    def _resolve(self, key, real: str, proc: psutil.Process):
        """Which locked app this process is: by name, else by its program file. Cached per process."""
        if key not in self._names:
            try:
                exe = proc.exe()
            except psutil.Error:  # e.g. an elevated process we may not inspect
                exe = None
            if real in self._apps:
                self._names[key] = real
                self.identity.learn(real, exe)  # remember the real app's fingerprint for renamed copies
            else:
                self._names[key] = self.identity.match(exe, self._apps)
        return self._names[key]

    def _handle(self, name: str, proc: psutil.Process, real: str = "") -> None:
        # `name` is the locked app; `real` the process's actual file name, which differs for a renamed copy.
        copy = f" (renamed copy: {real})" if real and real != name else ""
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
                self.ctx.audit.record("enforce_failed", f"{name} pid={proc.pid}{copy} cannot suspend: {exc}")
                return
            queue = self._pending.setdefault(name, [])
            first = not queue  # only the first frozen instance opens a prompt; the rest wait with it
            queue.append(proc)
            # Helpers it already started in the moment before this scan (often under other names, e.g.
            # a launcher's game or a browser's renderers) are frozen with it, and resumed or closed
            # with it too.
            queue.extend(self._freeze_children(proc))
            soft = self._relocking or name in self._soft
            if soft:
                self._soft.add(name)
        if not self._relocking:
            self.ctx.audit.record("blocked", f"{name} pid={proc.pid}{copy}")
        elif first:  # one line per app, not per helper process (a browser runs dozens)
            self.ctx.audit.record("relocked", f"{name} (open app frozen until unlocked)")
        if first and not soft:
            self.on_locked(name)  # held (re-locked) apps are prompted for when the user is back: reprompt_held()

    def _freeze_children(self, proc: psutil.Process) -> list:
        frozen = []
        try:
            children = proc.children(recursive=True)
        except psutil.Error:
            return frozen
        for child in children:
            key = self._key(child)
            if key in self._seen:
                continue  # already handled on its own
            try:
                child.suspend()
            except psutil.Error:
                continue
            self._seen.add(key)
            frozen.append(child)
        return frozen

    # -- decisions ----------------------------------------------------------
    def relock(self, reason: str) -> None:
        """Lock again the locked apps that are open right now (and cancel unlock grants).

        Called when Windows locks or the user has been idle. The next scan freezes every running
        instance and holds it until the password (or face) is given again."""
        with self._lock:
            self._granted.clear()
            self._relock_requested = True
        self.ctx.audit.record("relock", reason)

    @staticmethod
    def _key(proc: psutil.Process):
        try:
            return proc.pid, proc.create_time()  # same key scan() uses
        except psutil.Error:
            return proc.pid, None

    def held(self) -> list:
        """Apps frozen by a re-lock that are waiting for the user to come back."""
        with self._lock:
            return sorted(n for n in self._soft if self._pending.get(n))

    def reprompt_held(self) -> None:
        """Ask again for each held app (the runtime calls this when the user is at the PC)."""
        for name in self.held():
            self.on_locked(name)

    def resolve(self, name: str, allowed: bool) -> None:
        """The prompt's answer: resume every waiting instance of `name`, or kill them.

        A HELD app (re-locked while open) is never killed: a refusal keeps it frozen and it is
        asked for again later, so an unattended prompt can't destroy unsaved work."""
        with self._lock:
            if not allowed and name in self._soft:
                count = len(self._pending.get(name, []))
                self.ctx.audit.record("held", f"{name} ({count} process(es)) stays frozen")
                return
            procs = self._pending.pop(name, [])
            self._soft.discard(name)
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
        """Kill a process and all its children (browsers start many helper processes)."""
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
            self._soft.clear()
        for proc in procs:
            try:
                proc.resume()
            except psutil.Error:
                pass
        if procs:
            self.ctx.audit.record("released_on_exit", f"{len(procs)} process(es)")

    # -- thread -------------------------------------------------------------
    def start(self) -> None:
        self._unfreeze_leftovers()
        self._thread = threading.Thread(target=self._loop, name="guard", daemon=True)
        self._thread.start()

    def _unfreeze_leftovers(self) -> None:
        """A previous copy that was killed (and restarted by the watchdog) leaves locked apps frozen.
        Windows counts freezes, so freezing them again would need TWO unlocks to resume. Resume them
        once here; the first scan, a moment later, freezes them again and asks for the password."""
        if self.ctx.dev:
            return
        apps = set(self.ctx.db.list_apps())
        for proc in psutil.process_iter(["name", "status"]):
            try:
                if proc.info["status"] == psutil.STATUS_STOPPED and (proc.info["name"] or "").lower() in apps:
                    proc.resume()
            except psutil.Error:
                continue

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
    while a password prompt was open). Callers decide whether a password is needed: the CLI asks
    for one while a guard is running, because then a frozen app is waiting at its prompt."""
    locked = set(ctx.db.list_apps())
    identity = Identifier(ctx.db)
    resumed = 0
    for proc in psutil.process_iter(["name", "status"]):
        try:
            if proc.info["status"] != psutil.STATUS_STOPPED:
                continue
            name = (proc.info["name"] or "").lower()
            if name in locked or identity.match(proc.exe(), locked):
                proc.resume()
                resumed += 1
        except psutil.Error:
            continue
    if resumed:
        ctx.audit.record("released_manually", f"{resumed} process(es)")
    return resumed
