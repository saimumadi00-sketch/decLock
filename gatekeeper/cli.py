"""Command-line interface: `python -m gatekeeper <command>`.

Every command that changes something asks for the Gatekeeper password first (_require_auth),
and goes through the same db/auth/audit objects as the desktop app, so both always agree.
"""

import argparse
import getpass
import os
import sys
import time

from . import auth
from .app import open_context, run_guard
from .config import MIN_PASSWORD_LEN
from .dashdata import SingleInstance, lock_app, normalize_exe, validate_app
from .devmode import DevModeRefused, resolve_dev_mode
from .idle import IdleLocker
from .matcher import (THRESHOLD_RANGE, TIMEOUT_RANGE, WEAK_THRESHOLD, enrolment_current, face_unlock_enabled,
                      get_threshold, get_timeout)
from .usb import UsbPolicy


def _require_auth(ctx) -> bool:
    """Prompt for the password (hidden input). Uses the shared lockout, so the CLI can't be used
    to brute-force faster than the dashboard."""
    if not auth.has_password(ctx.db):
        print("No password set. Run: python -m gatekeeper init")
        return False
    wait = auth.lockout_remaining(ctx.db)
    if wait > 0:
        print(f"Locked out after too many wrong passwords. Try again in {int(wait) + 1}s.")
        return False
    if auth.check_password(ctx.db, getpass.getpass("Password: "), ctx.audit):
        return True
    ctx.audit.record("bad_password", "cli")
    print("Wrong password.")
    return False


def cmd_init(ctx, args) -> int:
    # Changing an existing password needs the old one; the very first one doesn't.
    if auth.has_password(ctx.db) and not _require_auth(ctx):
        return 1
    from .enrolment import BLOCKED_MESSAGE, setup_blocked
    if setup_blocked(ctx.db, ctx.enrolment):
        ctx.audit.record("setup_blocked", "first-run setup refused: this user was set up before")
        print(BLOCKED_MESSAGE)
        return 1
    new = getpass.getpass(f"New password (min {MIN_PASSWORD_LEN} chars): ")
    if new != getpass.getpass("Repeat: "):
        print("Passwords differ.")
        return 1
    try:
        auth.set_password(ctx.db, new)
    except ValueError as exc:  # too short
        print(exc)
        return 1
    ctx.audit.record("password_set")
    if ctx.enrolment:
        ctx.enrolment.mark()
    print("Password saved.")
    return 0


def cmd_add(ctx, args) -> int:
    # Same validation as the dashboard: normalizes the name and refuses Windows system programs.
    _name, error = validate_app(args.name)
    if error:
        print(error)
        return 1
    if not _require_auth(ctx):
        return 1
    name, _error = lock_app(ctx, args.name)  # also fingerprints a given .exe path / running copies
    print(f"Locked: {name}")
    return 0


def cmd_remove(ctx, args) -> int:
    from . import schedule
    name = normalize_exe(args.name)
    if not _require_auth(ctx):
        return 1
    if not ctx.db.remove_app(name):
        print(f"{name} was not in the list.")
        return 1
    schedule.set_window(ctx.db, name, "")  # drop its schedule too, so re-adding starts clean
    ctx.audit.record("app_removed", name)
    print(f"Unlocked: {name}")
    return 0


def cmd_list(ctx, args) -> int:
    apps = ctx.db.list_apps()
    print("\n".join(apps) if apps else "(no locked apps)")
    return 0


def cmd_usb(ctx, args) -> int:
    policy = UsbPolicy(ctx)
    if args.action == "status":  # read-only, no password needed
        print(f"USB storage: {policy.status()} (Gatekeeper wants it {'blocked' if policy.wanted() else 'allowed'})")
        return 0
    if not _require_auth(ctx):
        return 1
    try:
        policy.block() if args.action == "block" else policy.allow()
    except PermissionError as exc:  # writing HKLM needs Administrator
        print(exc)
        return 1
    state = "blocked" if args.action == "block" else "allowed"
    print(f"USB storage {state}" + (" (dev: log only, registry untouched)." if ctx.dev else "."))
    return 0


def cmd_face(ctx, args) -> int:
    from .face_store import FaceStore
    store = FaceStore(ctx.db, ctx.keys)
    # -- read-only actions ------------------------------------------------------------------
    if args.action == "status":
        print(f"Face samples enrolled: {store.count()}"
              + ("" if not store.count() or enrolment_current(ctx.db) else "  (made by older models: re-enrol)"))
        print(f"Face unlock:           {'on' if face_unlock_enabled(ctx.db) else 'off'}")
        print(f"Threshold:             {get_threshold(ctx.db):.2f} (higher = stricter)")
        print(f"Timeout:               {get_timeout(ctx.db):g}s, then falls back to the password")
        return 0
    if args.action == "test":
        # A preview window with live scores; it changes nothing, so it needs no password.
        from .faces import FaceEngine, ModelError
        from .matcher import FaceMatcher, run_test_window
        enrolled = store.embeddings()
        if not enrolled:
            print("Nothing enrolled. Run: python -m gatekeeper face enroll")
            return 1
        try:
            run_test_window(FaceMatcher(FaceEngine(), enrolled, get_threshold(ctx.db)), args.camera)
        except (ModelError, RuntimeError) as exc:
            print(exc)
            return 1
        return 0
    # -- everything below changes settings or face data -------------------------------------
    if not _require_auth(ctx):
        return 1
    if args.action in ("threshold", "timeout"):
        low, high = THRESHOLD_RANGE if args.action == "threshold" else TIMEOUT_RANGE
        if args.value is None or not low <= args.value <= high:
            print(f"Give a value between {low} and {high}, e.g. face {args.action} {(low + high) / 2:g}")
            return 1
        ctx.db.set_setting(f"face_{args.action}", args.value)
        ctx.audit.record(f"face_{args.action}_set", str(args.value))
        print(f"Face {args.action} set to {args.value:g}.")
        if args.action == "threshold" and args.value < WEAK_THRESHOLD:
            print(f"Warning: below {WEAK_THRESHOLD}; other people's faces start to match.")
        return 0
    if args.action in ("enable", "disable"):
        ctx.db.set_setting("face_unlock", "1" if args.action == "enable" else "0")
        ctx.audit.record(f"face_unlock_{args.action}d")
        print(f"Face unlock {args.action}d.")
        return 0
    if args.action == "clear":
        store.clear()
        ctx.audit.record("face_cleared")
        print("Face data deleted.")
        return 0
    # action == "enroll": collect samples in an OpenCV window, then store them encrypted.
    from .enroll import Enroller, run_camera_enrolment
    from .faces import FaceEngine, ModelError
    try:
        enroller = Enroller(FaceEngine(), store, args.samples, snapshots=not args.no_snapshots)
        print("Look at the camera. Keep one face in view; Esc cancels.")
        completed = run_camera_enrolment(enroller, args.camera)
    except (ModelError, RuntimeError) as exc:
        print(exc)
        return 1
    if not completed:
        print("Enrolment cancelled or timed out; nothing was saved.")
        return 1
    ctx.audit.record("face_enrolled", f"{enroller.commit()} samples")
    print("Enrolled. Samples are stored encrypted.")
    return 0


def cmd_idle_lock(ctx, args) -> int:
    if args.minutes < 0:
        print("Minutes must be 0 (off) or more.")
        return 1
    if not _require_auth(ctx):
        return 1
    ctx.db.set_setting("idle_lock_minutes", args.minutes)
    ctx.audit.record("idle_lock_set", str(args.minutes))
    print("Idle lock off." if args.minutes == 0 else f"Workstation locks after {args.minutes} idle minute(s).")
    return 0


def cmd_lock_now(ctx, args) -> int:
    # Locking Windows only makes things safer, so no password is needed.
    IdleLocker(ctx, 0).lock("manual_lock", "cli")
    return 0


def cmd_log(ctx, args) -> int:
    if not _require_auth(ctx):
        return 1
    if args.action == "export":
        if not args.value:
            print("Usage: log export <file.csv>")
            return 1
        print(f"Exported {ctx.audit.export_csv(args.value)} entries to {args.value}")
    elif args.action == "prune":
        days = int(ctx.db.get_setting("log_retention_days", 90))
        print(f"Removed {ctx.audit.prune(days)} entries older than {days} days." if days > 0
              else "Retention is off (keep forever).")
    elif args.action == "retention":
        if not args.value or not args.value.isdigit():
            print("Usage: log retention <days>   (0 keeps everything)")
            return 1
        ctx.db.set_setting("log_retention_days", int(args.value))
        ctx.audit.record("retention_set", args.value)
        print(f"Log retention: {'keep forever' if args.value == '0' else args.value + ' days'}.")
    elif args.action == "reset":
        backup = ctx.directory / "audit-before-reset.csv"  # never throw the old log away silently
        ctx.audit.export_csv(backup)
        ctx.audit.reset()
        print(f"Old log saved to {backup}; fresh chain started.")
    return 0


def cmd_release(ctx, args) -> int:
    """Recovery after a crash: un-freeze locked apps the dead guard left suspended.

    While a guard IS running, a frozen app is waiting at its unlock prompt; resuming it then would
    skip the password, so that case needs the password.
    """
    from . import winapi
    from .guard import release_suspended
    installed, admin = bool(getattr(sys, "frozen", False)), winapi.is_admin()
    # The lock below is per data folder, so a copy of the database in another folder would look
    # like "no guard running" and skip the password. The installed build therefore refuses
    # --data-dir here and always asks (the elevated uninstaller is the one exception).
    if installed and args.data_dir and not admin:
        print("release does not accept --data-dir in the installed build.")
        return 1
    lock = SingleInstance(ctx.directory)
    guard_running = not lock.acquire()
    needs_password = guard_running or (installed and not admin and auth.has_password(ctx.db))
    if needs_password and not _require_auth(ctx):
        lock.release()
        return 1
    try:
        print(f"Resumed {release_suspended(ctx)} frozen process(es).")
    finally:
        lock.release()
    return 0


def cmd_status(ctx, args) -> int:
    ok, bad = ctx.audit.verify()
    idle = float(ctx.db.get_setting("idle_lock_minutes", 0))
    print(f"mode:      {'DEV (log only)' if ctx.dev else 'enforcing'}")
    print(f"usb:       {UsbPolicy(ctx).status()}")
    print(f"idle lock: {'off' if idle == 0 else f'{idle:g} min'}")
    print(f"data dir:  {ctx.directory}")
    print(f"password:  {'set' if auth.has_password(ctx.db) else 'NOT SET'}")
    print(f"apps:      {len(ctx.db.list_apps())} locked")
    print(f"log chain: {'ok' if ok else f'BROKEN at entry {bad}'}")
    return 0 if ok else 2  # exit code 2 = tampering, usable from scripts


def cmd_verify_log(ctx, args) -> int:
    ok, bad = ctx.audit.verify()
    print("Audit chain intact." if ok else f"Audit chain BROKEN at entry {bad}.")
    return 0 if ok else 2


def cmd_run(ctx, args) -> int:
    """Headless guard: no dashboard, only the unlock prompt appears."""
    if not auth.has_password(ctx.db):
        print("Set a password first: python -m gatekeeper init")
        return 1
    if not ctx.dev and not ctx.db.list_apps():
        print("No locked apps configured; nothing to guard.")
        return 1
    lock = SingleInstance(ctx.directory)  # never two guards fighting over the same processes
    if not lock.acquire():
        print("Gatekeeper is already running (the desktop app or another guard).")
        return 1
    try:
        run_guard(ctx)
    finally:
        lock.release()
    return 0


def cmd_gui(ctx, args) -> int:
    """The desktop app: dashboard + guard in one process."""
    from .dashboard import run_dashboard
    lock = SingleInstance(ctx.directory)
    # An elevated relaunch starts while the old copy is still shutting down, so wait a moment.
    if not lock.acquire(wait=6):
        installed = _installed_guard(args)
        outcome = claim_guard_slot(lock, lambda: older_guards(ctx.directory)) if installed else "exit"
        if outcome == "lockless":
            ctx.audit.record("lock_squatted", "the single-instance lock is held by something that is not "
                                              "Gatekeeper; guarding without it")
            return _run_gui(ctx, args, run_dashboard, lock)
        if outcome == "lock":
            return _run_gui(ctx, args, run_dashboard, lock)
        message = "Gatekeeper is already running. Look for it in your taskbar."
        print(message)
        if installed:
            # No blocking dialog here: a copy left waiting on a message box would look like a
            # running guard to the watchdog while the real one is gone.
            return 1
        try:  # the windowed build has no console, so say it in a dialog too
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo("Gatekeeper", message)
            root.destroy()
        except Exception:
            pass
        return 1
    return _run_gui(ctx, args, run_dashboard, lock)


def _installed_guard(args) -> bool:
    return bool(getattr(sys, "frozen", False)) and bool(args.service)


def claim_guard_slot(lock, older_guards, linger: float = 4.0, poll: float = 0.5,
                     clock=time.monotonic, sleep=time.sleep) -> str:
    """Installed build, after the single-instance lock could not be taken. Returns:

      "lock"      the lock came free (the old copy finished shutting down): guard normally
      "lockless"  nothing that is really Gatekeeper is older than us, so whatever holds the lock is
                  not a guard (the lock was squatted): guard anyway, without it
      "exit"      a real, older guard is running: leave within `linger` seconds, never linger longer
    """
    deadline = clock() + linger
    while True:
        if lock.acquire():
            return "lock"
        if not older_guards():
            return "lockless"
        if clock() >= deadline:
            return "exit"
        sleep(poll)


def older_guards(directory) -> list:
    """PIDs of real guards for `directory` in this session that started before this process."""
    import psutil

    from .watchdog import guards_in, session_of
    me = psutil.Process()
    mine = (me.create_time(), me.pid)
    session = session_of(os.getpid())
    if session is None:
        return []
    found = []
    for pid, _suspended in guards_in(session, directory):
        if pid == me.pid:
            continue
        try:
            if (psutil.Process(pid).create_time(), pid) < mine:
                found.append(pid)
        except psutil.Error:
            continue
    return found


def _run_gui(ctx, args, run_dashboard, lock) -> int:
    # The arguments an elevated copy of this exact instance would need (see winapi.relaunch_elevated).
    relaunch = ((["--dev"] if ctx.dev else []) + (["--service"] if args.service else [])
                + ["--data-dir", str(ctx.directory), "gui"])
    try:
        run_dashboard(ctx, minimized=args.minimized, relaunch_args=relaunch)
    finally:
        lock.release()
    return 0


def _ask_uninstall(gate) -> bool:
    """The unlock-style password prompt, worded for uninstalling. Denies on cancel or timeout."""
    import tkinter as tk
    from .ui import FADE_OUT_MS, UnlockPrompt
    root = tk.Tk()
    root.withdraw()
    result = []

    def done(allowed: bool) -> None:
        result.append(allowed)
        root.after(FADE_OUT_MS + 100, root.quit)  # let the prompt fade out first

    UnlockPrompt(root, "Gatekeeper", gate.verify, done, max_attempts=3,
                 on_failure=lambda: gate.record("bad_password", "uninstaller"), lockout=gate.lockout,
                 title="Uninstall Gatekeeper?",
                 prompt=f"Enter the Gatekeeper password of {gate.owner} to uninstall it.",
                 confirm_text="Uninstall")
    root.mainloop()
    root.destroy()
    return bool(result and result[0])


def confirm_uninstall_main() -> int:
    """Run by the uninstaller before it removes anything. Exit code 0 = go ahead, 1 = refused.
    Handled before open_context, so it never creates a data folder in the admin's profile."""
    from .uninstall import confirm_uninstall
    return 0 if confirm_uninstall(_ask_uninstall, warn=_warn_uninstall) else 1


def _warn_uninstall(message: str) -> None:
    """Tell the administrator why the uninstall was refused (the windowed build has no console)."""
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Gatekeeper", message)
        root.destroy()
    except Exception:
        print(message, file=sys.stderr)


def release_folders_main() -> int:
    """Run by the uninstaller: unlock every folder any Windows user locked, so nothing is left
    inaccessible once Gatekeeper is gone. Administrator only: for anyone else it would be a way
    around the folder lock."""
    from . import winapi
    if not winapi.is_admin():
        print("release-folders needs Administrator rights (the uninstaller runs it).")
        return 1
    from .config import data_dir
    from .folders import release_everywhere
    from .uninstall import candidate_dirs
    failed = []
    released = release_everywhere(candidate_dirs(data_dir()), failed=failed)
    print(f"Unlocked {released} folder(s).")
    if failed:
        # Their folders may still be locked; say where, so an administrator can unlock them by hand
        # (icacls "<folder>" /remove:d *S-1-1-0, see folders.py).
        print("Could not read the Gatekeeper data in: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


COMMANDS = {"init": cmd_init, "add": cmd_add, "remove": cmd_remove, "list": cmd_list,
            "status": cmd_status, "verify-log": cmd_verify_log, "run": cmd_run, "gui": cmd_gui,
            "usb": cmd_usb, "idle-lock": cmd_idle_lock, "lock-now": cmd_lock_now,
            "face": cmd_face, "log": cmd_log, "release": cmd_release}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Hidden commands (installer, uninstaller, scheduled task): only as the first word after the
    # options, so e.g. `gatekeeper add watchdog` still means "lock an app called watchdog".
    hidden = next((a for a in argv if not a.startswith("-")), "")
    if hidden == "confirm-uninstall":
        return confirm_uninstall_main()
    if hidden == "release-folders":
        return release_folders_main()
    if hidden == "watchdog":  # the SYSTEM scheduled task runs it (it refuses to run as anyone else)
        from .watchdog import main as watchdog_main
        return watchdog_main()
    if hidden in ("install-watchdog", "remove-watchdog"):
        from . import winapi
        from .watchdog import install_task, remove_task
        if not winapi.is_admin():
            print("This needs Administrator rights (the installer runs it).")
            return 1
        return 0 if (install_task() if hidden == "install-watchdog" else remove_task()) else 1
    parser = argparse.ArgumentParser(prog="gatekeeper")
    parser.add_argument("--dev", action="store_true", help="log only; never kill, block or lock")
    parser.add_argument("--service", action="store_true", help=argparse.SUPPRESS)  # set by the installer
    parser.add_argument("--data-dir", help="override data directory")
    sub = parser.add_subparsers(dest="command", required=True)
    # One sub-parser per command; only some commands take extra arguments.
    for name in COMMANDS:
        p = sub.add_parser(name)
        if name in ("add", "remove"):
            p.add_argument("name", help="executable name, e.g. notepad.exe")
        elif name == "usb":
            p.add_argument("action", choices=["block", "allow", "status"])
        elif name == "face":
            p.add_argument("action", choices=["enroll", "status", "clear", "test", "threshold", "timeout",
                                              "enable", "disable"])
            p.add_argument("value", nargs="?", type=float, help="for threshold / timeout")
            p.add_argument("--samples", type=int, default=5)
            p.add_argument("--camera", type=int, default=0)
            p.add_argument("--no-snapshots", action="store_true", help="store embeddings only")
        elif name == "log":
            p.add_argument("action", choices=["export", "prune", "retention", "reset"])
            p.add_argument("value", nargs="?", help="file for export, days for retention")
        elif name == "idle-lock":
            p.add_argument("minutes", type=float, help="idle minutes before locking; 0 turns it off")
        elif name == "gui":
            p.add_argument("--minimized", action="store_true", help="start minimized (used at logon)")
    args = parser.parse_args(argv)
    try:
        dev = resolve_dev_mode(args.dev, args.service)
    except DevModeRefused as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 3
    # Only the headless guard logs to the console; other commands keep their output clean.
    ctx = open_context(dev, args.data_dir, console=args.command == "run")
    try:
        return COMMANDS[args.command](ctx, args)
    finally:
        ctx.db.close()
