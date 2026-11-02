"""The watchdog: keeps every user's Gatekeeper running, even against Task Manager.

Gatekeeper runs as the signed-in user, so that user (or anyone at their unlocked PC) can end it.
The watchdog runs as SYSTEM, started at boot by a scheduled task the installer creates
("Gatekeeper watchdog"). A standard user can't end a SYSTEM process or stop that task.
Every POLL seconds it:

  * starts Gatekeeper again in any signed-in user's session where it is missing, if that user has
    set Gatekeeper up (killing it now buys about two seconds; the restarted copy freezes locked
    apps that are open again and puts folder locks back);
  * resumes a Gatekeeper process that someone suspended (frozen it instead of killing it);
  * puts the USB block back if a user wants it and it was turned off (it runs as SYSTEM, so unlike
    Gatekeeper itself it may change that setting). It only ever BLOCKS: allowing USB still needs
    an Administrator, so editing your own settings file can't open USB through the watchdog.

Because the installed Gatekeeper comes back when closed, "Quit" becomes "Pause protection" there.
Administrators can still stop the watchdog (that is unavoidable without a kernel driver).

The decisions live in Watchdog (testable anywhere); the Windows calls are in the functions below it.
"""

import ctypes
import logging
import logging.handlers
import os
import sqlite3
import sys
import time
from pathlib import Path

log = logging.getLogger("gatekeeper.watchdog")

TASK_NAME = "Gatekeeper watchdog"
POLL = 2.0
GUARD_EXE = "gatekeeperw.exe"
# A guard that keeps crashing is restarted less often, but never more than BACKOFF_MAX apart: a
# script that kills it the moment it starts must not be able to stretch the gap to minutes.
BACKOFF_START, BACKOFF_MAX = 2.0, 10.0
# Launches in a row that never leave a guard running before the watchdog fails closed and
# disconnects the session (the user signs back in with their Windows password). Covers a guard
# that cannot start at all (its lock or database made unusable), so protection never stays off.
MAX_MISSES = 5

# The only command lines a real guard is started with (the startup shortcut, the watchdog itself and
# the dashboard's elevated relaunch). Anything else that runs gatekeeperw.exe (face test, the
# uninstall prompt, a copy pointed at another data folder) is not a guard and must not count as one.
_GUARD_COMMANDS = {"gui", "run"}
_GUARD_FLAGS = {"--service", "--minimized"}


def _same_dir(a, b) -> bool:
    try:
        return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))
    except OSError:
        return False


def canonical_guard_args(args, expected_dir=None) -> bool:
    """True if `args` (the command line after the exe) is how a real guard for `expected_dir` runs:
    --service, the gui or run command, optionally --minimized, and either no --data-dir or one that
    points at the user's own Gatekeeper folder."""
    args = list(args)
    seen_command = seen_service = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--data-dir":
            if i + 1 >= len(args) or expected_dir is None or not _same_dir(args[i + 1], expected_dir):
                return False
            i += 2
            continue
        if a.startswith("--data-dir="):
            if expected_dir is None or not _same_dir(a.split("=", 1)[1], expected_dir):
                return False
        elif a in _GUARD_FLAGS:
            seen_service = seen_service or a == "--service"
        elif a in _GUARD_COMMANDS and not seen_command:
            seen_command = True
        else:
            return False  # --dev, another command, or a stray argument
        i += 1
    return seen_command and seen_service


def read_settings(directory: Path, keys, strict: bool = False):
    """Read a few settings from a user's database read-only (never creates or changes anything).

    No database file -> {}. A database that exists but can't be read (locked, corrupt) -> {} too,
    or None with `strict`, so callers that must fail closed can tell "no password" from "couldn't
    look"."""
    failed = None if strict else {}
    db = Path(directory) / "gatekeeper.db"
    if not db.is_file():
        return {}
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return failed
    try:
        marks = ",".join("?" * len(keys))
        rows = conn.execute(f"SELECT key, value FROM settings WHERE key IN ({marks})", list(keys)).fetchall()
        return dict(rows)
    except sqlite3.Error:
        return failed
    finally:
        conn.close()


def protected(directory, sid=None, enrolled=None) -> bool:
    """Has this user set Gatekeeper up? Only then is their Gatekeeper kept running.

    Yes if their database holds a password, OR if the add-only ProgramData marker says they set it
    up before. The marker matters: renaming, deleting or locking the database must not make the
    watchdog decide the user is unprotected and stop restarting the guard (that failed open)."""
    if directory:
        found = read_settings(directory, ["password_hash"], strict=True)
        if found is None:  # the database is there but can't be read: locked or damaged, never "unprotected"
            log.warning("cannot read %s; treating the user as protected", directory)
            return True
        if "password_hash" in found:
            return True
    if sid and enrolled is not None:
        try:
            return bool(enrolled(sid))
        except Exception:
            log.warning("enrolment check failed for %s", sid, exc_info=True)
    return False


def usb_wanted(dirs, now: float) -> bool:
    """Should USB storage be blocked right now? Yes if any user wants the block and nobody has a
    password-approved temporary allow running."""
    wanted, temporary = False, False
    for d in dirs:
        s = read_settings(d, ["usb_block", "usb_allow_until"])
        if s.get("usb_block") == "1":
            wanted = True
            try:
                temporary = temporary or float(s.get("usb_allow_until") or 0) > now
            except ValueError:
                pass
    return wanted and not temporary


class Watchdog:
    """One tick() = one round of checks. Every Windows call is passed in, so tests use fakes."""

    def __init__(self, sessions, data_dir_for, guards_in, launch, resume, all_dirs, usb_enforce,
                 clock=time.monotonic, wall=time.time, enrolled=None, disconnect=None):
        self.sessions = sessions        # () -> [(session_id, user_sid)] for signed-in users
        self.data_dir_for = data_dir_for  # user_sid -> that user's Gatekeeper folder (or None)
        self.guards_in = guards_in      # session_id -> [(pid, suspended?)] of the real Gatekeeper
        self.launch = launch            # session_id -> start Gatekeeper in that session (True if started)
        self.resume = resume            # pid -> resume a suspended process
        self.all_dirs = all_dirs        # () -> every user's Gatekeeper folder (for the USB decision)
        self.usb_enforce = usb_enforce  # () -> put the USB block back; True if it had to
        self.clock, self.wall = clock, wall
        self._next = {}                 # session_id -> earliest time to try starting it again
        self._delay = {}                # session_id -> current backoff
        self.enrolled = enrolled        # user_sid -> True if the ProgramData marker says they set up
        self.disconnect = disconnect    # session_id -> fail closed (disconnect the session)
        self._misses = {}               # session_id -> launches in a row that left no guard running

    def tick(self) -> None:
        now = self.clock()
        live = set()
        for session, sid in self.sessions():
            live.add(session)
            directory = self.data_dir_for(sid)
            if not protected(directory, sid, self.enrolled):
                continue
            guards = self.guards_in(session, directory)
            if guards:  # running: a later kill is restarted at once
                self._delay.pop(session, None)
                self._next.pop(session, None)
                self._misses.pop(session, None)
                for pid, suspended in guards:
                    if suspended:
                        log.warning("Gatekeeper (pid %s) in session %s was suspended; resuming it", pid, session)
                        self.resume(pid)
                continue
            if now < self._next.get(session, 0):
                continue
            delay = self._delay.get(session, 0)
            self._delay[session] = min(BACKOFF_MAX, delay * 2 if delay else BACKOFF_START)
            self._next[session] = now + self._delay[session]
            # Launched last time and gone again: one more miss. Too many and we fail closed.
            self._misses[session] = self._misses[session] + 1 if session in self._misses else 0
            if self._misses[session] >= MAX_MISSES and self.disconnect is not None:
                log.error("Gatekeeper keeps failing to run in session %s; disconnecting it", session)
                self._misses[session] = 0
                try:
                    self.disconnect(session)
                except Exception:
                    log.exception("could not disconnect session %s", session)
                continue
            log.warning("Gatekeeper is not running in session %s; starting it", session)
            if not self.launch(session):
                log.error("could not start Gatekeeper in session %s", session)
        for gone in set(self._next) - live:  # signed out: forget its backoff
            self._next.pop(gone, None)
            self._delay.pop(gone, None)
            self._misses.pop(gone, None)
        try:
            if usb_wanted(self.all_dirs(), self.wall()) and self.usb_enforce():
                log.warning("USB storage block had been turned off; restored it")
        except Exception:
            log.exception("USB check failed")

    def run(self, stop=None) -> None:
        while stop is None or not stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("watchdog tick failed")
            time.sleep(POLL)


# -- Windows plumbing (SYSTEM only) ------------------------------------------------------------------

def _w():
    from ctypes import wintypes
    return wintypes


class _Api:
    """Private wtsapi32/kernel32/advapi32/userenv handles with every prototype declared.

    ctypes.windll.<dll> is shared by the whole process (other modules declare their own prototypes on
    it), and a call without prototypes passes Python ints as 32-bit C ints and reads results back as
    32-bit ints, which breaks 64-bit handles. use_last_error keeps GetLastError for error messages."""

    def __init__(self):
        from ctypes import wintypes as w
        self.wts = wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
        self.k32 = k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.adv = adv = ctypes.WinDLL("advapi32", use_last_error=True)
        self.env = env = ctypes.WinDLL("userenv", use_last_error=True)
        P = ctypes.POINTER
        for fn, args, res in (
            (wts.WTSEnumerateSessionsW, [w.HANDLE, w.DWORD, w.DWORD, P(ctypes.c_void_p), P(w.DWORD)], w.BOOL),
            (wts.WTSFreeMemory, [ctypes.c_void_p], None),
            (wts.WTSQueryUserToken, [w.ULONG, P(w.HANDLE)], w.BOOL),
            (wts.WTSDisconnectSession, [w.HANDLE, w.DWORD, w.BOOL], w.BOOL),
            (k32.CloseHandle, [w.HANDLE], w.BOOL),
            (k32.ProcessIdToSessionId, [w.DWORD, P(w.DWORD)], w.BOOL),
            (adv.DuplicateTokenEx, [w.HANDLE, w.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, P(w.HANDLE)],
             w.BOOL),
            (adv.CreateProcessAsUserW, [w.HANDLE, w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL,
                                        w.DWORD, ctypes.c_void_p, w.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p],
             w.BOOL),
            (env.CreateEnvironmentBlock, [P(ctypes.c_void_p), w.HANDLE, w.BOOL], w.BOOL),
            (env.DestroyEnvironmentBlock, [ctypes.c_void_p], w.BOOL),
        ):
            fn.argtypes, fn.restype = args, res

    @staticmethod
    def error() -> OSError:
        return ctypes.WinError(ctypes.get_last_error())


_API = None


def _api() -> _Api:
    global _API
    if _API is None:
        _API = _Api()
    return _API


def session_of(pid: int):
    """The session a process runs in, or None if Windows won't say."""
    from ctypes import wintypes
    session = wintypes.DWORD()
    if not _api().k32.ProcessIdToSessionId(pid, ctypes.byref(session)):
        return None
    return session.value


def signed_in_sessions() -> list:
    """[(session_id, user_sid)] for sessions with a signed-in user (active or switched away from)."""
    w = _w()
    api = _api()

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", w.DWORD), ("pWinStationName", w.LPWSTR), ("State", ctypes.c_int)]

    raw, count = ctypes.c_void_p(), w.DWORD()
    if not api.wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(raw), ctypes.byref(count)):
        raise api.error()
    try:
        buf = ctypes.cast(raw, ctypes.POINTER(WTS_SESSION_INFOW))
        ids = [buf[i].SessionId for i in range(count.value) if buf[i].State in (0, 4)]  # Active, Disconnected
    finally:
        api.wts.WTSFreeMemory(raw)
    result = []
    for session in ids:
        token = _user_token(session)
        if token:
            try:
                result.append((session, _token_sid(token)))
            finally:
                api.k32.CloseHandle(token)
    return result


def _user_token(session: int):
    w = _w()
    token = w.HANDLE()
    if not _api().wts.WTSQueryUserToken(session, ctypes.byref(token)):
        return None  # nobody signed in there (or not running as SYSTEM)
    return token


def _token_sid(token) -> str:
    from .enrolment import token_user_sid
    return token_user_sid(token)


def data_dir_for(sid: str):
    """%USERPROFILE%\\AppData\\Roaming\\Gatekeeper for a user SID (from the ProfileList)."""
    import winreg
    try:
        key = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as k:
            profile = os.path.expandvars(winreg.QueryValueEx(k, "ProfileImagePath")[0])
    except OSError:
        return None
    return Path(profile) / "AppData" / "Roaming" / "Gatekeeper"


def install_dir() -> Path:
    return Path(sys.executable).resolve().parent


def guards_in(session: int, directory=None) -> list:
    """[(pid, suspended)] of real guards in a session: the INSTALLED gatekeeperw.exe (by path, so a
    look-alike with the same name doesn't count), started with a guard command line for this user's
    own data folder (so face test, the uninstall prompt or a copy on another folder don't count)."""
    import psutil
    want = os.path.normcase(str(install_dir() / GUARD_EXE))
    found = []
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info["name"] or "").lower() != GUARD_EXE or os.path.normcase(proc.info["exe"] or "") != want:
                continue
            if session_of(proc.pid) != session:
                continue
            if not canonical_guard_args(proc.cmdline()[1:], directory):
                continue  # the watchdog, or gatekeeperw.exe running something that isn't the guard
            found.append((proc.pid, proc.status() == psutil.STATUS_STOPPED))
        except psutil.Error:
            continue
    return found


def resume(pid: int) -> None:
    import psutil
    try:
        psutil.Process(pid).resume()
    except psutil.Error as exc:
        log.warning("could not resume %s: %s", pid, exc)


def launch(session: int, api=None, token_for=None) -> bool:
    """Start Gatekeeper (minimized) on the user's desktop in `session`, as that user.
    `api` and `token_for` are only passed by tests."""
    import subprocess
    w = _w()
    api = api or _api()
    token_for = token_for or _user_token
    exe = str(install_dir() / GUARD_EXE)
    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([exe, "--service", "gui", "--minimized"]))

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
                    ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD), ("dwYSize", w.DWORD),
                    ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                    ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                    ("lpReserved2", ctypes.c_void_p), ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE),
                    ("hStdError", w.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

    token = token_for(session)
    if not token:
        return False
    primary, env = w.HANDLE(), ctypes.c_void_p()
    try:
        # MAXIMUM_ALLOWED, SecurityImpersonation (2), TokenPrimary (1)
        if not api.adv.DuplicateTokenEx(token, 0x02000000, None, 2, 1, ctypes.byref(primary)):
            raise api.error()
        if not api.env.CreateEnvironmentBlock(ctypes.byref(env), primary, False):
            # Never fall back to "no environment block": CreateProcessAsUser would then hand the
            # guard the WATCHDOG's (SYSTEM's) environment, so it would look for its data in the
            # SYSTEM profile instead of the user's. Not launching counts as a miss instead.
            env = ctypes.c_void_p()
            raise api.error()
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        ok = api.adv.CreateProcessAsUserW(primary, exe, cmdline, None, None, False,
                                          0x00000400,  # CREATE_UNICODE_ENVIRONMENT
                                          env, str(install_dir()), ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            raise api.error()
        api.k32.CloseHandle(pi.hThread)
        api.k32.CloseHandle(pi.hProcess)
        return True
    except OSError as exc:
        log.error("could not start Gatekeeper in session %s: %s", session, exc)
        return False
    finally:
        if env:
            api.env.DestroyEnvironmentBlock(env)
        if primary:
            api.k32.CloseHandle(primary)
        api.k32.CloseHandle(token)


def disconnect_session(session: int) -> bool:
    """Fail closed: disconnect a session whose guard cannot be kept running. Its programs keep
    running, but nobody can use them until the user signs in again with the Windows password."""
    if session in (None, 0xFFFFFFFF):  # WTS_CURRENT_SESSION would be the watchdog's own session
        return False
    return bool(_api().wts.WTSDisconnectSession(None, session, False))


def enrolled_sid(sid: str) -> bool:
    """Does the add-only ProgramData folder hold a valid enrolment marker for this user?"""
    from .enrolment import Enrolment, default_folder
    return Enrolment(default_folder(), sid=sid).enrolled()


def usb_enforce() -> bool:
    """Put the full USB block back (USBSTOR, UASPStor, removable-storage policy) if any switch is off."""
    from .usb import BLOCKED, WinExtras, WinRegistry
    reg, extras = WinRegistry(), WinExtras()
    if reg.get_start() is None:
        return False  # no USB storage driver on this PC
    if reg.get_start() == BLOCKED and extras.blocked():
        return False
    reg.set_start(BLOCKED)
    extras.set(True)
    return True


def is_system() -> bool:
    from .enrolment import current_sid
    try:
        return current_sid() == "S-1-5-18"
    except Exception:
        return False


def _setup_log() -> None:
    from .enrolment import _program_data
    folder = _program_data() / "Gatekeeper"
    folder.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(folder / "watchdog.log", maxBytes=500_000, backupCount=2,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger("gatekeeper")
    root.setLevel(logging.INFO)
    root.addHandler(handler)


def main() -> int:
    """`gatekeeperw.exe watchdog`, run by the scheduled task as SYSTEM."""
    if not is_system():
        print("The watchdog only runs as SYSTEM (the installer sets it up).")
        return 1
    _setup_log()
    from .uninstall import candidate_dirs
    log.info("watchdog started")
    Watchdog(signed_in_sessions, data_dir_for, guards_in, launch, resume,
             lambda: candidate_dirs(None), usb_enforce, enrolled=enrolled_sid,
             disconnect=disconnect_session).run()
    return 0


# -- installing the scheduled task (Administrator) ---------------------------------------------------

def install_task() -> bool:
    """Register and start the SYSTEM task. Runs at boot, never times out, restarts if it fails."""
    from .usb import _powershell
    exe = str(install_dir() / GUARD_EXE).replace("'", "''")
    script = (
        f"$a = New-ScheduledTaskAction -Execute '{exe}' -Argument '--service watchdog'\n"
        "$t = New-ScheduledTaskTrigger -AtStartup\n"
        "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n"
        "$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
        "-ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) "
        "-MultipleInstances IgnoreNew -StartWhenAvailable\n"
        f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null\n"
        f"Start-ScheduledTask -TaskName '{TASK_NAME}'\n")
    return _powershell(script)


def remove_task() -> bool:
    from .usb import _powershell
    return _powershell(f"Stop-ScheduledTask -TaskName '{TASK_NAME}' -ErrorAction SilentlyContinue\n"
                       f"Unregister-ScheduledTask -TaskName '{TASK_NAME}' -Confirm:$false -ErrorAction SilentlyContinue")
