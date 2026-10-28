import logging
import queue
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path

from . import auth
from .audit import AuditLog
from .config import data_dir, setup_logging
from .crypto import KeyStore
from .db import Database
from .guard import Guard
from .idle import IdleLocker
from .matcher import build_face_unlock
from .ui import UnlockPrompt
from .usb import UsbPolicy, UsbWatcher

log = logging.getLogger("gatekeeper.app")


@dataclass
class Context:
    dev: bool
    directory: Path
    db: Database
    audit: AuditLog
    keys: KeyStore


def open_context(dev: bool, directory=None, console: bool = True) -> Context:
    path = data_dir(directory, dev)
    setup_logging(path, dev, console)
    db = Database(path / "gatekeeper.db")
    return Context(dev, path, db, AuditLog(db, path / "audit.head"), KeyStore(path))


def startup_checks(ctx: Context, root) -> None:
    """Verify the audit chain and apply log retention. A broken chain raises an alarm but
    never stops protection."""
    ok, bad = ctx.audit.verify()
    if not ok:
        log.critical("Audit log tampering detected at entry %s", bad)
        ctx.audit.record("tamper_detected", f"audit chain broken at {bad}")
        from tkinter import messagebox
        root.after(500, lambda: messagebox.showwarning(
            "Gatekeeper", f"The audit log failed its integrity check (at {bad}).\n"
            "Someone may have edited or deleted entries. Export the log, then investigate."))
    last = ctx.db.conn.execute(
        "SELECT event FROM audit_log WHERE event IN ('guard_start','guard_stop') ORDER BY id DESC LIMIT 1").fetchone()
    if last and last["event"] == "guard_start":
        # The guard never logged a clean stop: it was killed, crashed, or the PC lost power.
        ctx.audit.record("unclean_shutdown", "previous guard session ended without a clean stop")
    days = int(ctx.db.get_setting("log_retention_days", 90))
    if days > 0:
        ctx.audit.prune(days)


def run_guard(ctx: Context) -> None:
    root = tk.Tk()
    root.withdraw()
    events: "queue.Queue[str]" = queue.Queue()
    guard = Guard(ctx, events.put)
    state = {"busy": False}
    engines = []

    def get_engine():
        if not engines:  # load the models once, on first use
            from .faces import FaceEngine
            engines.append(FaceEngine())
        return engines[0]

    def show_next() -> None:
        if state["busy"] or events.empty():
            return
        name = events.get()
        state["busy"] = True

        def done(allowed: bool) -> None:
            state["busy"] = False
            guard.resolve(name, allowed)

        def face_result(face_state: str, score) -> None:
            shown = "n/a" if score is None else f"{score:.2f}"
            ctx.audit.record({"matched": "face_unlock", "failed": "face_failed"}.get(face_state, "face_unavailable"),
                             f"{name} best_score={shown}")

        UnlockPrompt(
            root, name, lambda pw: auth.check_password(ctx.db, pw, ctx.audit), done,
            on_failure=lambda: ctx.audit.record("bad_password", name),
            lockout=lambda: auth.lockout_remaining(ctx.db),
            face=build_face_unlock(ctx, get_engine), on_face_result=face_result)

    def pump() -> None:
        show_next()
        root.after(200, pump)

    startup_checks(ctx, root)
    ctx.audit.record("guard_start", "dev" if ctx.dev else "enforcing")
    log.info("Guard running (%s). Ctrl+C to stop.", "DEV: log only" if ctx.dev else "enforcing")
    guard.start()
    usb_watcher = UsbWatcher(ctx, UsbPolicy(ctx))
    usb_watcher.start()
    idle_minutes = float(ctx.db.get_setting("idle_lock_minutes", 0))
    idle_locker = IdleLocker(ctx, idle_minutes) if idle_minutes > 0 else None
    if idle_locker:
        idle_locker.start()
    root.after(200, pump)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        usb_watcher.stop()
        if idle_locker:
            idle_locker.stop()
        guard.stop()
        ctx.audit.record("guard_stop")
