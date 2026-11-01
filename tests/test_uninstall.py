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


def test_each_user_is_checked_against_their_own_password(tmp_path):
    users = tmp_path / "Users"
    gate = UninstallGate([make_profile(users, "alice", "alice-password"),
                          make_profile(users, "bob", "bob-password"), make_profile(users, "carol")])
    assert [u.owner for u in gate.users] == ["alice", "bob"]  # carol set no password
    alice, bob = gate.users
    assert alice.verify("alice-password") and not alice.verify("bob-password")
    assert bob.verify("bob-password") and not bob.verify("alice-password")
    gate.close()


def test_wrong_passwords_hit_that_users_lockout(tmp_path):
    d = make_profile(tmp_path / "Users", "alice", "alice-password")
    gate = UninstallGate([d])
    alice = gate.users[0]
    for _ in range(auth.FREE_FAILURES):
        assert not alice.verify("wrong-password")
    assert alice.lockout() > 0
    assert not alice.verify("alice-password")  # even the right one is refused while locked out
    gate.close()


def _two_users(tmp_path, monkeypatch):
    users = tmp_path / "Users"
    dirs = [make_profile(users, "alice", "alice-password"), make_profile(users, "bob", "bob-password")]
    monkeypatch.setattr(uninstall, "data_dir", lambda: dirs[0])
    monkeypatch.setattr(uninstall, "candidate_dirs", lambda own: dirs)
    return dirs


def test_uninstall_needs_every_users_password(tmp_path, monkeypatch):
    _two_users(tmp_path, monkeypatch)
    passwords = {"alice": "alice-password", "bob": "bob-password"}
    asked = []

    def own_password_only_for_bob(user):  # bob set up Gatekeeper and knows only his own password
        asked.append(user.owner)
        return user.verify("bob-password")
    monkeypatch.setattr(cli, "_ask_uninstall", own_password_only_for_bob)
    assert cli.main(["confirm-uninstall"]) == 1
    assert asked == ["alice"]  # refused at the first user whose password he doesn't know

    monkeypatch.setattr(cli, "_ask_uninstall", lambda user: user.verify(passwords[user.owner]))
    assert cli.main(["confirm-uninstall"]) == 0


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
