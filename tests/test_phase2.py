import pytest

from gatekeeper.app import open_context
from gatekeeper.idle import IdleLocker
from gatekeeper.usb import ALLOWED, BLOCKED, UsbPolicy, UsbWatcher


class FakeRegistry:
    def __init__(self, start=ALLOWED, deny=False):
        self.start, self.deny, self.writes = start, deny, []

    def get_start(self):
        return self.start

    def set_start(self, value):
        if self.deny:
            raise PermissionError("Administrator rights are required")
        self.start = value
        self.writes.append(value)


@pytest.fixture
def ctx(tmp_path):
    c = open_context(False, tmp_path, console=False)
    yield c
    c.db.close()


@pytest.fixture
def dev_ctx(tmp_path):
    c = open_context(True, tmp_path, console=False)
    yield c
    c.db.close()


def test_usb_block_and_allow(ctx):
    reg = FakeRegistry()
    policy = UsbPolicy(ctx, reg)
    policy.block()
    assert reg.start == BLOCKED and policy.status() == "blocked" and policy.wanted()
    policy.allow()
    assert reg.start == ALLOWED and not policy.wanted()


def test_usb_block_without_admin_changes_nothing(ctx):
    policy = UsbPolicy(ctx, FakeRegistry(deny=True))
    with pytest.raises(PermissionError):
        policy.block()
    assert not policy.wanted()


def test_usb_dev_mode_leaves_registry_alone(dev_ctx):
    reg = FakeRegistry()
    UsbPolicy(dev_ctx, reg).block()
    assert reg.writes == []


def test_usb_enforce_restores_reverted_block(ctx):
    reg = FakeRegistry()
    policy = UsbPolicy(ctx, reg)
    policy.block()
    reg.start = ALLOWED  # someone undoes it
    assert policy.enforce() is True and reg.start == BLOCKED
    assert policy.enforce() is False


def test_usb_watcher_logs_new_drive_and_failed_repair_once(ctx):
    reg = FakeRegistry()
    policy = UsbPolicy(ctx, reg)
    policy.block()
    reg.start, reg.deny = ALLOWED, True
    mounts = {"E:\\"}
    watcher = UsbWatcher(ctx, policy, mounts_fn=lambda: set(mounts))
    mounts.add("F:\\")
    watcher.tick()
    watcher.tick()
    events = [r["event"] for r in ctx.db.conn.execute("SELECT event FROM audit_log")]
    assert events.count("usb_storage_seen") == 1
    assert events.count("usb_enforce_failed") == 1


def test_idle_lock_fires_once_per_idle_period(ctx):
    idle, locks = [0], []
    locker = IdleLocker(ctx, 1, idle_fn=lambda: idle[0], lock_fn=lambda: locks.append(1) or True)
    locker.tick()
    assert locks == []
    idle[0] = 61
    locker.tick()
    locker.tick()
    assert locks == [1]
    idle[0] = 0
    locker.tick()
    idle[0] = 90
    locker.tick()
    assert locks == [1, 1]


def test_idle_lock_dev_mode_never_locks(dev_ctx):
    locks = []
    locker = IdleLocker(dev_ctx, 1, idle_fn=lambda: 999, lock_fn=lambda: locks.append(1) or True)
    locker.tick()
    assert locks == []


def test_idle_seconds_real_api():
    from gatekeeper.winapi import idle_seconds
    assert idle_seconds() >= 0
