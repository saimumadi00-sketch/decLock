"""The uninstaller's password check (gatekeeper/uninstall.py)."""

from gatekeeper import auth, cli, uninstall
from gatekeeper.app import open_context
from gatekeeper.uninstall import UninstallGate, candidate_dirs


def make_profile(users, name, password=None):
    """A fake Windows profile with a Gatekeeper data folder (and optionally a password)."""
    d = users / name / "AppData" / "Roaming" / "Gatekeeper"
    ctx = open_context(False, d, console=False)
    if password:
        auth.set_password(ctx.db, password)
    ctx.db.close()
    return d


def test_finds_every_profile_once(tmp_path):
    users = tmp_path / "Users"
    a, b = make_profile(users, "alice", "alice-password"), make_profile(users, "bob")
    (users / "carol").mkdir()  # profile without Gatekeeper
    found = candidate_dirs(own=a, users_root=users)
    assert sorted(p.resolve() for p in found) == sorted([a.resolve(), b.resolve()])


def test_unprotected_installs_need_no_password(tmp_path):
    gate = UninstallGate([make_profile(tmp_path / "Users", "bob")])
    assert not gate.protected
    gate.close()


def test_password_of_any_profile_is_accepted(tmp_path):
    users = tmp_path / "Users"
    gate = UninstallGate([make_profile(users, "alice", "alice-password"),
                          make_profile(users, "bob", "bob-password")])
    assert gate.protected
    assert not gate.verify("wrong-password")
    assert gate.verify("bob-password")
    assert gate.verify("alice-password")
    gate.close()


def test_wrong_passwords_hit_the_shared_lockout(tmp_path):
    d = make_profile(tmp_path / "Users", "alice", "alice-password")
    gate = UninstallGate([d])
    for _ in range(auth.FREE_FAILURES):
        assert not gate.verify("wrong-password")
    assert gate.lockout() > 0
    assert not gate.verify("alice-password")  # even the right one is refused while locked out
    gate.close()


def test_confirm_uninstall_asks_and_logs(tmp_path, monkeypatch):
    d = make_profile(tmp_path / "Users", "alice", "alice-password")
    monkeypatch.setattr(uninstall, "data_dir", lambda: d)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda own: [own])
    monkeypatch.setattr(cli, "_ask_uninstall", lambda gate: gate.verify("wrong-password"))
    assert cli.main(["confirm-uninstall"]) == 1
    monkeypatch.setattr(cli, "_ask_uninstall", lambda gate: gate.verify("alice-password"))
    assert cli.main(["confirm-uninstall"]) == 0
    ctx = open_context(False, d, console=False)
    events = [r["event"] for r in ctx.db.conn.execute("SELECT event FROM audit_log")]
    ctx.db.close()
    assert "uninstall_refused" in events and "uninstall_allowed" in events


def test_confirm_uninstall_without_password_allows(tmp_path, monkeypatch):
    d = make_profile(tmp_path / "Users", "bob")
    monkeypatch.setattr(uninstall, "data_dir", lambda: d)
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda own: [own])
    monkeypatch.setattr(cli, "_ask_uninstall", lambda gate: (_ for _ in ()).throw(AssertionError("asked")))
    assert cli.main(["confirm-uninstall"]) == 0
