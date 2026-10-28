import subprocess
import time

import psutil
import pytest

from gatekeeper import auth
from gatekeeper.app import open_context
from gatekeeper.devmode import DevModeRefused, resolve_dev_mode
from gatekeeper.guard import Guard


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


def test_dev_mode_switches():
    assert resolve_dev_mode(cli_dev=True) is True
    assert resolve_dev_mode(environ={"GATEKEEPER_DEV": "1"}) is True
    assert resolve_dev_mode(environ={}) is False
    with pytest.raises(DevModeRefused):
        resolve_dev_mode(cli_dev=True, service=True)
    with pytest.raises(DevModeRefused):
        resolve_dev_mode(service=True, environ={"GATEKEEPER_DEV": "1"})


def test_password_hashing(ctx):
    assert not auth.has_password(ctx.db)
    auth.set_password(ctx.db, "correct horse battery")
    stored = ctx.db.get_setting("password_hash")
    assert stored.startswith("$2") and "correct" not in stored
    assert auth.verify_password(ctx.db, "correct horse battery")
    assert not auth.verify_password(ctx.db, "wrong password")
    with pytest.raises(ValueError):
        auth.set_password(ctx.db, "short")
    long_pw = "x" * 200
    auth.set_password(ctx.db, long_pw)
    assert not auth.verify_password(ctx.db, "x" * 100)


def test_audit_chain_detects_tampering(ctx):
    for i in range(5):
        ctx.audit.record("event", f"n={i}")
    assert ctx.audit.verify() == (True, None)
    with ctx.db.lock, ctx.db.conn:
        ctx.db.conn.execute("UPDATE audit_log SET detail='edited' WHERE id=3")
    assert ctx.audit.verify() == (False, 3)


def test_keystore_roundtrip_and_persistence(tmp_path):
    from gatekeeper.crypto import KeyStore
    token = KeyStore(tmp_path).encrypt(b"face-embedding")
    assert b"face-embedding" not in token
    assert KeyStore(tmp_path).decrypt(token) == b"face-embedding"
    assert b"face" not in (tmp_path / "key.bin").read_bytes()


def _spawn_ping():
    proc = subprocess.Popen(["ping.exe", "-t", "127.0.0.1"], stdout=subprocess.DEVNULL)
    time.sleep(0.3)
    return proc


def test_guard_suspends_then_kills_on_deny(ctx):
    ctx.db.add_app("ping.exe")
    victim = _spawn_ping()
    requested = []
    guard = Guard(ctx, requested.append)
    try:
        guard.scan()
        assert requested == ["ping.exe"]
        assert psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED
        guard.resolve("ping.exe", False)
        assert victim.wait(timeout=5) is not None
    finally:
        victim.kill()
        guard.stop()


def test_guard_resumes_on_allow_and_grants(ctx):
    ctx.db.add_app("ping.exe")
    victim = _spawn_ping()
    guard = Guard(ctx, lambda n: None)
    try:
        guard.scan()
        guard.resolve("ping.exe", True)
        assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
        second = _spawn_ping()
        try:
            guard.scan()
            assert psutil.Process(second.pid).status() != psutil.STATUS_STOPPED
        finally:
            second.kill()
    finally:
        victim.kill()
        guard.stop()


def test_dev_mode_never_touches_processes(dev_ctx):
    dev_ctx.db.add_app("ping.exe")
    victim = _spawn_ping()
    requested = []
    guard = Guard(dev_ctx, requested.append)
    try:
        guard.scan()
        assert requested == []
        assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
        assert victim.poll() is None
    finally:
        victim.kill()


def test_shutdown_releases_suspended_processes(ctx):
    ctx.db.add_app("ping.exe")
    victim = _spawn_ping()
    guard = Guard(ctx, lambda n: None)
    try:
        guard.scan()
        guard.stop()
        assert psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
    finally:
        victim.kill()
