"""Wires the pieces together (Context) and holds start-up logic shared by the CLI and the GUI."""

import logging
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .enrolment import Enrolment, sync as sync_enrolment
from .logwitness import LogWitness
from .config import DATA_DIR_ENV, data_dir, data_dir_env_ignored, setup_logging
from .crypto import KeyStore
from .db import Database

log = logging.getLogger("gatekeeper.app")


@dataclass
class Context:
    """Everything a command needs, passed around instead of globals."""
    dev: bool
    directory: Path
    db: Database
    audit: AuditLog
    keys: KeyStore
    enrolment: Enrolment = None  # marker outside %APPDATA% that this user set up before


def open_context(dev: bool, directory=None, console: bool = True) -> Context:
    """Open (or create) the data folder, database, audit log and key store."""
    path = data_dir(directory, dev)
    setup_logging(path, dev, console)
    db = Database(path / "gatekeeper.db")
    ctx = Context(dev, path, db, AuditLog(db, path / "audit.head"), KeyStore(path), Enrolment())
    sync_enrolment(db, ctx.enrolment)  # installs set up before markers existed get one now
    ctx.audit.witness = LogWitness(ctx.enrolment)
    if directory is None and data_dir_env_ignored():
        log.warning("%s is set but ignored in the installed build", DATA_DIR_ENV)
        ctx.audit.record("env_ignored", f"{DATA_DIR_ENV} is set; the installed build ignores it")
    return ctx


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
    with ctx.db.lock:  # the guard threads share this connection
        last = ctx.db.conn.execute(
            "SELECT event FROM audit_log WHERE event IN ('guard_start','guard_stop') ORDER BY id DESC LIMIT 1").fetchone()
    if last and last["event"] == "guard_start":
        # The guard never logged a clean stop: it was killed, crashed, or the PC lost power.
        ctx.audit.record("unclean_shutdown", "previous guard session ended without a clean stop")
    days = int(ctx.db.get_setting("log_retention_days", 90))  # 0 = keep forever
    if days > 0:
        ctx.audit.prune(days)


def run_guard(ctx: Context) -> None:
    """Headless guard (no dashboard): the unlock prompt is the only window."""
    import tkinter as tk
    from .runtime import GuardRuntime
    root = tk.Tk()
    root.withdraw()  # an invisible root window; prompts are its Toplevels
    runtime = GuardRuntime(ctx, root)
    runtime.start()
    log.info("Ctrl+C to stop.")
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()
