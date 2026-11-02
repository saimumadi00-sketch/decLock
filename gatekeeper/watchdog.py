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


def read_settings(directory: Path, keys) -> dict:
    """Read a few settings from a user's database read-only (never creates or changes anything)."""
    db = Path(directory) / "gatekeeper.db"
    if not db.is_file():
        return {}
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return {}
    try:
        marks = ",".join("?" * len(keys))
        rows = conn.execute(f"SELECT key, value FROM settings WHERE key IN ({marks})", list(keys)).fetchall()
        return dict(rows)
    except sqlite3.Error:
        return {}
    finally:
        conn.close()


def protected(directory) -> bool:
    """Has this user set a Gatekeeper password? Only then is their Gatekeeper kept running."""
    return bool(directory) and "password_hash" in read_settings(directory, ["password_hash"])


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
                 clock=time.monotonic, wall=time.time):
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

    def tick(self) -> None:
        now = self.clock()
        live = set()
        for session, sid in self.sessions():
            live.add(session)
            directory = self.data_dir_for(sid)
            if not protected(directory):
                continue
            guards = self.guards_in(session)
            if guards:  # running: a later kill is restarted at once
                self._delay.pop(session, None)
                self._next.pop(session, None)
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
            log.warning("Gatekeeper is not running in session %s; starting it", session)
            if not self.launch(session):
                log.error("could not start Gatekeeper in session %s", session)
        for gone in set(self._next) - live:  # signed out: forget its backoff
            self._next.pop(gone, None)
            self._delay.pop(gone, None)
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


def signed_in_sessions() -> list:
    """[(session_id, user_sid)] for sessions with a signed-in user (active or switched away from)."""
    w = _w()
    wtsapi32 = ctypes.windll.wtsapi32

    class WTS_SESSION_INFOW(ctypes.Structure):
        _fields_ = [("SessionId", w.DWORD), ("pWinStationName", w.LPWSTR), ("State", ctypes.c_int)]

    buf, count = ctypes.POINTER(WTS_SESSION_INFOW)(), w.DWORD()
    if not wtsapi32.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(buf), ctypes.byref(count)):
        raise ctypes.WinError()
    try:
        ids = [buf[i].SessionId for i in range(count.value) if buf[i].State in (0, 4)]  # Active, Disconnected
    finally:
        wtsapi32.WTSFreeMemory(buf)
    result = []
    for session in ids:
        token = _user_token(session)
        if token:
            try:
                result.append((session, _token_sid(token)))
            finally:
                ctypes.windll.kernel32.CloseHandle(token)
    return result


def _user_token(session: int):
    w = _w()
    token = w.HANDLE()
    if not ctypes.windll.wtsapi32.WTSQueryUserToken(w.ULONG(session), ctypes.byref(token)):
        return None  # nobody signed in there (or not running as SYSTEM)
    return token


def _token_sid(token) -> str:
    w = _w()
    advapi32, kernel32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    size = w.DWORD()
    advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
    buf = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)):
        raise ctypes.WinError()
    sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
    text = w.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(ctypes.c_void_p(sid), ctypes.byref(text)):
        raise ctypes.WinError()
    try:
        return text.value
    finally:
        kernel32.LocalFree(text)


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


def guards_in(session: int) -> list:
    """[(pid, suspended)] of the INSTALLED gatekeeperw.exe running in a session (by path, so a
    look-alike process with the same name doesn't count)."""
    import psutil
    want = os.path.normcase(str(install_dir() / GUARD_EXE))
    to_session = ctypes.windll.kernel32.ProcessIdToSessionId
    found = []
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info["name"] or "").lower() != GUARD_EXE or os.path.normcase(proc.info["exe"] or "") != want:
                continue
            sid = ctypes.c_ulong()
            if not to_session(proc.pid, ctypes.byref(sid)) or sid.value != session:
                continue
            if "watchdog" in " ".join(proc.cmdline()):
                continue  # the watchdog itself (session 0 anyway)
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


def launch(session: int) -> bool:
    """Start Gatekeeper (minimized) on the user's desktop in `session`, as that user."""
    import subprocess
    w = _w()
    advapi32, kernel32, userenv = ctypes.windll.advapi32, ctypes.windll.kernel32, ctypes.windll.userenv
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

    token = _user_token(session)
    if not token:
        return False
    primary, env = w.HANDLE(), ctypes.c_void_p()
    try:
        # MAXIMUM_ALLOWED, SecurityImpersonation (2), TokenPrimary (1)
        if not advapi32.DuplicateTokenEx(token, 0x02000000, None, 2, 1, ctypes.byref(primary)):
            raise ctypes.WinError()
        if not userenv.CreateEnvironmentBlock(ctypes.byref(env), primary, False):
            env = ctypes.c_void_p()
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\default"
        pi = PROCESS_INFORMATION()
        advapi32.CreateProcessAsUserW.argtypes = [
            w.HANDLE, w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD, ctypes.c_void_p,
            w.LPCWSTR, ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]
        ok = advapi32.CreateProcessAsUserW(primary, exe, cmdline, None, None, False,
                                           0x00000400,  # CREATE_UNICODE_ENVIRONMENT
                                           env, str(install_dir()), ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            raise ctypes.WinError()
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)
        return True
    except OSError as exc:
        log.error("CreateProcessAsUser failed: %s", exc)
        return False
    finally:
        if env:
            userenv.DestroyEnvironmentBlock(env)
        if primary:
            kernel32.CloseHandle(primary)
        kernel32.CloseHandle(token)


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
             lambda: candidate_dirs(None), usb_enforce).run()
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
