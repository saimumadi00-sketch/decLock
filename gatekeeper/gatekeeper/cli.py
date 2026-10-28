import argparse
import getpass
import sys

from . import auth
from .app import open_context, run_guard
from .config import MIN_PASSWORD_LEN, PROTECTED_PROCESSES
from .devmode import DevModeRefused, resolve_dev_mode
from .idle import IdleLocker
from .matcher import THRESHOLD_RANGE, face_unlock_enabled, get_threshold, get_timeout
from .usb import UsbPolicy


def _normalize(name: str) -> str:
    name = name.strip().lower()
    return name if "." in name else name + ".exe"


def _require_auth(ctx) -> bool:
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
    if auth.has_password(ctx.db) and not _require_auth(ctx):
        return 1
    new = getpass.getpass(f"New password (min {MIN_PASSWORD_LEN} chars): ")
    if new != getpass.getpass("Repeat: "):
        print("Passwords differ.")
        return 1
    try:
        auth.set_password(ctx.db, new)
    except ValueError as exc:
        print(exc)
        return 1
    ctx.audit.record("password_set")
    print("Password saved.")
    return 0


def cmd_add(ctx, args) -> int:
    name = _normalize(args.name)
    if name in PROTECTED_PROCESSES:
        print(f"{name} is protected and cannot be locked (would risk locking you out).")
        return 1
    if not _require_auth(ctx):
        return 1
    ctx.db.add_app(name)
    ctx.audit.record("app_added", name)
    print(f"Locked: {name}")
    return 0


def cmd_remove(ctx, args) -> int:
    name = _normalize(args.name)
    if not _require_auth(ctx):
        return 1
    if not ctx.db.remove_app(name):
        print(f"{name} was not in the list.")
        return 1
    ctx.audit.record("app_removed", name)
    print(f"Unlocked: {name}")
    return 0


def cmd_list(ctx, args) -> int:
    apps = ctx.db.list_apps()
    print("\n".join(apps) if apps else "(no locked apps)")
    return 0


def cmd_usb(ctx, args) -> int:
    policy = UsbPolicy(ctx)
    if args.action == "status":
        print(f"USB storage: {policy.status()} (Gatekeeper wants it {'blocked' if policy.wanted() else 'allowed'})")
        return 0
    if not _require_auth(ctx):
        return 1
    try:
        policy.block() if args.action == "block" else policy.allow()
    except PermissionError as exc:
        print(exc)
        return 1
    state = "blocked" if args.action == "block" else "allowed"
    print(f"USB storage {state}" + (" (dev: log only, registry untouched)." if ctx.dev else "."))
    return 0


def cmd_face(ctx, args) -> int:
    from .face_store import FaceStore
    store = FaceStore(ctx.db, ctx.keys)
    if args.action == "status":
        print(f"Face samples enrolled: {store.count()}")
        print(f"Face unlock:           {'on' if face_unlock_enabled(ctx.db) else 'off'}")
        print(f"Threshold:             {get_threshold(ctx.db):.2f} (higher = stricter)")
        print(f"Timeout:               {get_timeout(ctx.db):g}s, then falls back to the password")
        return 0
    if args.action == "test":
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
    if not _require_auth(ctx):
        return 1
    if args.action in ("threshold", "timeout"):
        low, high = THRESHOLD_RANGE if args.action == "threshold" else (2, 30)
        if args.value is None or not low <= args.value <= high:
            print(f"Give a value between {low} and {high}, e.g. face {args.action} {(low + high) / 2:g}")
            return 1
        ctx.db.set_setting(f"face_{args.action}", args.value)
        ctx.audit.record(f"face_{args.action}_set", str(args.value))
        print(f"Face {args.action} set to {args.value:g}.")
        if args.action == "threshold" and args.value < 0.363:
            print("Warning: below SFace's published 0.363 threshold; false accepts become likely.")
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
        backup = ctx.directory / "audit-before-reset.csv"
        ctx.audit.export_csv(backup)
        ctx.audit.reset()
        print(f"Old log saved to {backup}; fresh chain started.")
    return 0


def cmd_release(ctx, args) -> int:
    from .guard import release_suspended
    print(f"Resumed {release_suspended(ctx)} frozen process(es).")
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
    return 0 if ok else 2


def cmd_verify_log(ctx, args) -> int:
    ok, bad = ctx.audit.verify()
    print("Audit chain intact." if ok else f"Audit chain BROKEN at entry {bad}.")
    return 0 if ok else 2


def cmd_run(ctx, args) -> int:
    if not auth.has_password(ctx.db):
        print("Set a password first: python -m gatekeeper init")
        return 1
    if not ctx.dev and not ctx.db.list_apps():
        print("No locked apps configured; nothing to guard.")
        return 1
    run_guard(ctx)
    return 0


COMMANDS = {"init": cmd_init, "add": cmd_add, "remove": cmd_remove, "list": cmd_list,
            "status": cmd_status, "verify-log": cmd_verify_log, "run": cmd_run,
            "usb": cmd_usb, "idle-lock": cmd_idle_lock, "lock-now": cmd_lock_now,
            "face": cmd_face, "log": cmd_log, "release": cmd_release}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="gatekeeper")
    parser.add_argument("--dev", action="store_true", help="log only; never kill, block or lock")
    parser.add_argument("--service", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--data-dir", help="override data directory")
    sub = parser.add_subparsers(dest="command", required=True)
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
    args = parser.parse_args(argv)
    try:
        dev = resolve_dev_mode(args.dev, args.service)
    except DevModeRefused as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 3
    ctx = open_context(dev, args.data_dir, console=args.command == "run")
    try:
        return COMMANDS[args.command](ctx, args)
    finally:
        ctx.db.close()
