import logging
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .config import data_dir, setup_logging
from .crypto import KeyStore
from .db import Database

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
    """Headless guard (no dashboard): the unlock prompt is the only window."""
    import tkinter as tk
    from .runtime import GuardRuntime
    root = tk.Tk()
    root.withdraw()
    runtime = GuardRuntime(ctx, root)
    runtime.start()
    log.info("Ctrl+C to stop.")
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
