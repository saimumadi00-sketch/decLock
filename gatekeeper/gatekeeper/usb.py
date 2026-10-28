"""USB mass-storage blocking via the USBSTOR driver start type (needs Administrator).

Start=4 disables the driver, so newly plugged storage devices cannot mount; drives
already mounted keep working until removed. Keyboards, mice and other USB classes are
unaffected. The setting lives in the registry, not in this process, so it stays in
effect if Gatekeeper stops. Recovery without Gatekeeper (elevated prompt):
    reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR /v Start /t REG_DWORD /d 3 /f
"""

import logging
import threading

import psutil

log = logging.getLogger("gatekeeper.usb")

KEY = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
VALUE = "Start"
BLOCKED, ALLOWED = 4, 3
SETTING = "usb_block"


class WinRegistry:
    def get_start(self):
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY) as key:
                return winreg.QueryValueEx(key, VALUE)[0]
        except FileNotFoundError:
            return None

    def set_start(self, value: int) -> None:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, VALUE, 0, winreg.REG_DWORD, value)
        except PermissionError:
            raise PermissionError("Administrator rights are required to change USB storage policy.") from None


class UsbPolicy:
    def __init__(self, ctx, reg=None):
        self.ctx = ctx
        self.reg = reg or WinRegistry()

    def status(self) -> str:
        start = self.reg.get_start()
        return "unknown" if start is None else "blocked" if start == BLOCKED else "allowed"

    def wanted(self) -> bool:
        return self.ctx.db.get_setting(SETTING) == "1"

    def _apply(self, block: bool) -> None:
        verb = "blocked" if block else "allowed"
        if self.ctx.dev:
            log.info("[DEV] would set USB storage to %s; registry untouched", verb)
            self.ctx.audit.record(f"usb_{verb}_dev")
        else:
            self.reg.set_start(BLOCKED if block else ALLOWED)
            self.ctx.audit.record(f"usb_{verb}")
        self.ctx.db.set_setting(SETTING, "1" if block else "0")

    def block(self) -> None:
        self._apply(True)

    def allow(self) -> None:
        self._apply(False)

    def enforce(self) -> bool:
        """Re-apply the block if it is wanted but was reverted. Returns True if it repaired."""
        if self.ctx.dev or not self.wanted() or self.status() == "blocked":
            return False
        self.reg.set_start(BLOCKED)
        self.ctx.audit.record("usb_policy_restored", "block had been reverted")
        return True


def removable_mounts() -> set:
    return {p.mountpoint for p in psutil.disk_partitions(all=False) if "removable" in p.opts.lower()}


class UsbWatcher:
    """Audits newly appearing removable drives and repairs a reverted block."""

    def __init__(self, ctx, policy: UsbPolicy, mounts_fn=removable_mounts, poll: float = 5):
        self.ctx, self.policy, self.mounts_fn, self.poll = ctx, policy, mounts_fn, poll
        self._known = set(mounts_fn())
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
