"""GATEKEEPER_DATA_DIR must not be able to move an installed guard onto an empty folder."""

from pathlib import Path

from gatekeeper import config
from gatekeeper.app import open_context
from gatekeeper.dashdata import query_events


def test_env_honoured_in_development(tmp_path):
    env = {config.DATA_DIR_ENV: str(tmp_path / "custom"), "APPDATA": str(tmp_path / "roaming")}
    assert config.data_dir(environ=env, frozen=False) == tmp_path / "custom"
    assert not config.data_dir_env_ignored(env, frozen=False)


def test_env_ignored_in_installed_build(tmp_path):
    env = {config.DATA_DIR_ENV: str(tmp_path / "planted"), "APPDATA": str(tmp_path / "roaming")}
    path = config.data_dir(environ=env, frozen=True)
    assert path == tmp_path / "roaming" / config.APP_NAME
    assert not (tmp_path / "planted").exists()  # the planted folder is never created or used
    assert config.data_dir_env_ignored(env, frozen=True)


def test_explicit_data_dir_still_wins(tmp_path):
    env = {config.DATA_DIR_ENV: str(tmp_path / "planted"), "APPDATA": str(tmp_path / "roaming")}
    assert config.data_dir(tmp_path / "chosen", environ=env, frozen=True) == tmp_path / "chosen"


def test_dev_folder_unchanged(tmp_path):
    env = {"APPDATA": str(tmp_path)}
    assert config.data_dir(dev=True, environ=env, frozen=True) == Path(tmp_path) / (config.APP_NAME + "-dev")
    assert not config.data_dir_env_ignored(env, frozen=True)  # nothing set, nothing to report


def test_ignored_variable_is_audited(tmp_path, monkeypatch):
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setenv(config.DATA_DIR_ENV, str(tmp_path / "planted"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    ctx = open_context(False, console=False)
    try:
        assert ctx.directory == tmp_path / "roaming" / config.APP_NAME
        assert query_events(ctx.db, event="env_ignored")
    finally:
        ctx.db.close()
