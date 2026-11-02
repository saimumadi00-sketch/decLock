"""USB storage blocking (needs Administrator). Three switches, all in the registry, so they stay in
effect while Gatekeeper is not running:

  USBSTOR  Start=4   the classic USB mass-storage driver (pen drives, most external disks)
  UASPStor Start=4   the USB Attached SCSI driver many fast USB 3 SSDs use instead of USBSTOR
  Policy   Deny_All  Windows' "All Removable Storage classes: Deny all access" policy: phones
                     (MTP/WPD), card readers, CD/DVD. It can need a sign-out or restart to apply.

Drives already mounted keep working until removed. Keyboards, mice and other USB classes are
unaffected. Network shares, cloud uploads, email and Bluetooth are out of scope.

"Allow for N minutes" (the password-protected way to use a pen drive) lifts the block and
re-blocks it when the time is up: Gatekeeper does it if it is still running as Administrator, and
a one-shot SYSTEM scheduled task does it regardless.

Recovery without Gatekeeper (elevated prompt):
    reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f
    reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\UASPStor /v Start /t REG_DWORD /d 3 /f
    reg delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices /v Deny_All /f
"""

import base64
import logging
import os
import subprocess
import threading
import time

import psutil

log = logging.getLogger("gatekeeper.usb")

KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
VALUE = "Start"
BLOCKED, ALLOWED = 4, 3
SETTING = "usb_block"


class WinRegistry:
    """The real registry. Tests pass a fake with the same two methods."""
    def get_start(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY) as key:
                return winreg.QueryValueEx(key, VALUE)[0]
        except FileNotFoundError:
            return None  # USBSTOR not installed

    def set_start(self, value: int) -> None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, VALUE, 0, winreg.REG_DWORD, value)
        except PermissionError:
            raise PermissionError("Administrator rights are required to change USB storage policy.") from None


UASP_KEY = r"SYSTEM\CurrentControlSet\Services\UASPStor"
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices"
POLICY_VALUE = "Deny_All"
ALLOW_UNTIL = "usb_allow_until"           # epoch seconds while a temporary allow is running
REBLOCK_TASK = "Gatekeeper USB re-block"  # the one-shot SYSTEM scheduled task
TEMP_MINUTES_RANGE = (1, 240)


class WinExtras:
    """UASPStor and the removable-storage policy. Tests pass a fake with the same three methods."""

    def blocked(self) -> bool:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UASP_KEY) as key:
                if winreg.QueryValueEx(key, VALUE)[0] != BLOCKED:
                    return False
        except FileNotFoundError:
            pass  # no UASP driver on this PC: nothing to block
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY) as key:
                return winreg.QueryValueEx(key, POLICY_VALUE)[0] == 1
        except FileNotFoundError:
            return False

    def set(self, block: bool) -> None:
        import winreg
        try:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UASP_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, VALUE, 0, winreg.REG_DWORD, BLOCKED if block else ALLOWED)
            except FileNotFoundError:
                pass
            if block:
                with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, 0, winreg.KEY_SET_VALUE) as key:
                    winreg.SetValueEx(key, POLICY_VALUE, 0, winreg.REG_DWORD, 1)
            else:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, POLICY_VALUE)  # back to Windows' default, not "0"
                except FileNotFoundError:
                    pass
        except PermissionError:
            raise PermissionError("Administrator rights are required to change USB storage policy.") from None


def _powershell(script: str) -> bool:
    """Run a PowerShell script hidden. -EncodedCommand avoids every quoting problem."""
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")  # full path: never a powershell.exe planted earlier on PATH
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                                 "-EncodedCommand", encoded], capture_output=True, timeout=60,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("PowerShell failed: %s", exc)
        return False
    if result.returncode != 0:
        log.warning("PowerShell exited %s: %s", result.returncode, result.stderr[-500:])
    return result.returncode == 0


def reblock_command() -> str:
    """cmd.exe line that restores the full block (what the scheduled task runs)."""
    return (f'reg add "HKLM\\{KEY}" /v Start /t REG_DWORD /d {BLOCKED} /f & '
            f'reg query "HKLM\\{UASP_KEY}" >nul 2>&1 && reg add "HKLM\\{UASP_KEY}" /v Start /t REG_DWORD /d {BLOCKED} /f & '
            f'reg add "HKLM\\{POLICY_KEY}" /v {POLICY_VALUE} /t REG_DWORD /d 1 /f')


class TaskScheduler:
    """One-shot SYSTEM task that re-blocks USB at a given time (needs Administrator to create)."""

    def schedule(self, when: float) -> bool:
        script = (
            f"$a = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c {reblock_command()}'\n"
            f"$t = New-ScheduledTaskTrigger -Once -At ([DateTimeOffset]::FromUnixTimeSeconds({int(when)}).LocalDateTime)\n"
            "$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest\n"
            "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries\n"
            f"Register-ScheduledTask -TaskName '{REBLOCK_TASK}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null\n")
        return _powershell(script)

    def cancel(self) -> bool:
        return _powershell(f"Unregister-ScheduledTask -TaskName '{REBLOCK_TASK}' -Confirm:$false "
                           "-ErrorAction SilentlyContinue")


class UsbPolicy:
    """What Gatekeeper WANTS (db setting) vs what Windows HAS (registry), and switching between them."""
    def __init__(self, ctx, reg=None, extras=None, scheduler=None, clock=time.time):
        self.ctx = ctx
        real = reg is None
        self.reg = reg or WinRegistry()
        # With a fake registry (tests), the extra switches and the task scheduler are off unless passed.
        self.extras = extras if extras is not None else (WinExtras() if real else None)
        self.scheduler = scheduler if scheduler is not None else (TaskScheduler() if real else None)
        self.clock = clock

    def status(self) -> str:
        start = self.reg.get_start()
        return "unknown" if start is None else "blocked" if start == BLOCKED else "allowed"

    def wanted(self) -> bool:
        return self.ctx.db.get_setting(SETTING) == "1"

    def fully_blocked(self) -> bool:
        """Every switch is in the blocked position."""
        if self.status() != "blocked":
            return False
        try:
            return self.extras is None or self.extras.blocked()
        except OSError:
            return False

    def temporary_remaining(self) -> float:
        """Seconds left of a temporary allow (0 = none running)."""
        return max(0.0, float(self.ctx.db.get_setting(ALLOW_UNTIL, 0) or 0) - self.clock())

    def _set_all(self, block: bool) -> None:
        self.reg.set_start(BLOCKED if block else ALLOWED)
        if self.extras is not None:
            self.extras.set(block)

    def _end_temporary(self) -> None:
        if float(self.ctx.db.get_setting(ALLOW_UNTIL, 0) or 0):
            self.ctx.db.set_setting(ALLOW_UNTIL, 0)
            if self.scheduler is not None and not self.ctx.dev:
                self.scheduler.cancel()

    def _apply(self, block: bool) -> None:
        verb = "blocked" if block else "allowed"
        if self.ctx.dev:
            log.info("[DEV] would set USB storage to %s; registry untouched", verb)
            self.ctx.audit.record(f"usb_{verb}_dev")
        else:
            self._set_all(block)
            self.ctx.audit.record(f"usb_{verb}")
        self.ctx.db.set_setting(SETTING, "1" if block else "0")
        self._end_temporary()

    def block(self) -> None:
        self._apply(True)

    def allow(self) -> None:
        self._apply(False)

    def allow_temporarily(self, minutes) -> float:
        """Lift the block for `minutes`, then block again. Returns the minutes granted.

        The caller must have checked the password. Raises ValueError (bad minutes / not blocked)
        or PermissionError (not running as Administrator)."""
        try:
            minutes = float(minutes)
        except (TypeError, ValueError):
            raise ValueError("Minutes must be a number.") from None
        low, high = TEMP_MINUTES_RANGE
        if not low <= minutes <= high:
            raise ValueError(f"Minutes must be between {low} and {high}.")
        if not self.wanted():
            raise ValueError("USB storage is not blocked, so there is nothing to allow.")
        until = self.clock() + minutes * 60
        if self.ctx.dev:
            log.info("[DEV] would allow USB storage for %g min; registry untouched", minutes)
            self.ctx.audit.record("usb_temporary_allow_dev", f"{minutes:g} min")
        else:
            self._set_all(False)  # PermissionError here when not elevated: nothing has changed yet
            if self.scheduler is not None and not self.scheduler.schedule(until):
                self.ctx.audit.record("usb_reblock_task_failed", "only Gatekeeper itself will re-block")
            self.ctx.audit.record("usb_temporary_allow", f"{minutes:g} min")
        self.ctx.db.set_setting(ALLOW_UNTIL, until)
        return minutes

    def enforce(self) -> bool:
        """Re-apply the block if it is wanted but was reverted (or a temporary allow ran out).
        Returns True if it repaired."""
        if self.ctx.dev or not self.wanted():
            return False
        if self.temporary_remaining() > 0:
            return False  # a password-approved temporary allow is running
        expired = float(self.ctx.db.get_setting(ALLOW_UNTIL, 0) or 0) > 0
        if self.fully_blocked():
            if expired:  # the scheduled task already re-blocked: just tidy up
                self._end_temporary()
                self.ctx.audit.record("usb_temporary_allow_ended")
            return False
        self._set_all(True)  # PermissionError when not elevated; UsbWatcher reports it
        if expired:
            self._end_temporary()
            self.ctx.audit.record("usb_temporary_allow_ended")
        else:
            self.ctx.audit.record("usb_policy_restored", "block had been reverted")
        return True

    def alert(self) -> str:
        """A warning to show the owner, or "" when the real state matches what they asked for."""
        if not self.wanted() or self.temporary_remaining() > 0 or self.ctx.dev:
            return ""
        if self.status() == "unknown":
            return ""
        if not self.fully_blocked():
            return ("USB storage should be blocked but is not: the block was turned off outside Gatekeeper "
                    "(or only partly applied). Restart Gatekeeper as Administrator to restore it.")
        return ""


def removable_mounts() -> set:
    """Mount points of removable drives that are plugged in right now."""
    return {p.mountpoint for p in psutil.disk_partitions(all=False) if "removable" in p.opts.lower()}


class UsbWatcher:
    """Audits newly appearing removable drives and repairs a reverted block."""

    def __init__(self, ctx, policy: UsbPolicy, mounts_fn=removable_mounts, poll: float = 5):
        self.ctx, self.policy, self.mounts_fn, self.poll = ctx, policy, mounts_fn, poll
        self._known = set(mounts_fn())  # drives present at start are not "new"
        self._repair_failed = False
        self._stop = threading.Event()
        self._thread = None

    def tick(self) -> None:
        current = self.mounts_fn()
        for mount in sorted(current - self._known):
            self.ctx.audit.record("usb_storage_seen", mount)
        self._known = current
        try:
            self.policy.enforce()
            self._repair_failed = False
        except PermissionError as exc:
            if not self._repair_failed:  # log once, not every poll
                self._repair_failed = True
                self.ctx.audit.record("usb_enforce_failed", str(exc))

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="usb", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("usb tick failed")
            self._stop.wait(self.poll)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
