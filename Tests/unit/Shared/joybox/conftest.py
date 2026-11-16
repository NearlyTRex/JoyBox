# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import logger
from joybox import programs
from joybox import config
from joybox import environment
from joybox import locker
from joybox import lockerinfo
from joybox import ollama
from joybox import commandoptions
from joybox import sandbox
from joybox import webfetch


# Locker backups, recorded instead of copied
@pytest.fixture
def backups(monkeypatch):
    calls = []

    def backup(src, dest_rel_path, **kwargs):
        calls.append((src, dest_rel_path, kwargs))
        return True

    monkeypatch.setattr(locker, "convert_to_relative_path", lambda path: "relative/" + os.path.basename(path))
    monkeypatch.setattr(locker, "backup", backup)
    return calls


# The url a webpage search settles on, and every search asked for
@pytest.fixture
def webpage_url(monkeypatch):
    holder = {"url": None, "asked": []}

    def get_matching_url(**kwargs):
        holder["asked"].append(kwargs)
        return holder["url"]

    monkeypatch.setattr(webfetch, "get_matching_url", get_matching_url)
    return holder


@pytest.fixture
def game_tree(tmp_path, monkeypatch):
    # A real metadata, locker and cache layout, since GameInfo reads its json
    # off disk and derives everything else from that path.
    roots = {
        "json": tmp_path / "metadata" / "Json",
        "locker": tmp_path / "locker",
        "cache": tmp_path / "cache",
        "metadata": tmp_path / "metadata",
    }
    for path in roots.values():
        path.mkdir(parents = True, exist_ok = True)

    monkeypatch.setattr(
        environment, "get_game_json_metadata_root_dir", lambda: str(roots["json"]))
    monkeypatch.setattr(
        environment, "get_locker_root_dir", lambda locker_type = None: str(roots["locker"]))
    monkeypatch.setattr(environment, "get_cache_root_dir", lambda: str(roots["cache"]))
    monkeypatch.setattr(
        environment, "get_game_metadata_root_dir", lambda: str(roots["metadata"]))
    monkeypatch.setattr(
        lockerinfo, "get_primary_remote_locker_type", lambda: config.LockerType.LOCAL)
    return roots


# An Ollama server reached through an SSH tunnel's local end
@pytest.fixture
def tunneled(monkeypatch):
    values = {"ollama_ssh_host": "testuser@llm"}
    monkeypatch.setattr(
        ollama.settings, "get_value",
        lambda section, field, default_value = None, throw_exception = True: values.get(field, default_value))
    monkeypatch.setattr(ollama, "get_api_base", lambda: "http://localhost:11444")
    return values


# Wine and Sandboxie prefixes and the platforms they run on
@pytest.fixture
def installed_runners(monkeypatch):
    # Neither runner is installed on the machine running the tests, and the
    # lookup raises rather than returning nothing.
    monkeypatch.setattr(sandbox, "get_wine_command", lambda: "/tools/wine")
    monkeypatch.setattr(sandbox, "get_sandboxie_command", lambda: "/tools/start.exe")


@pytest.fixture
def wine_platform(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: True)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: False)


@pytest.fixture
def sandboxie_platform(monkeypatch, installed_runners):
    monkeypatch.setattr(sandbox.platform_info, "is_wine_platform", lambda: False)
    monkeypatch.setattr(sandbox.platform_info, "is_sandboxie_platform", lambda: True)


@pytest.fixture
def cached_game(monkeypatch):
    monkeypatch.setattr(sandbox.commandbase, "is_windows_executable_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_cached_game_command", lambda cmd: True)
    monkeypatch.setattr(sandbox.commandbase, "is_local_sandboxed_program_command", lambda cmd: False)


@pytest.fixture
def wine_prefix(tmp_path):
    prefix = tmp_path / "prefix"
    (prefix / "dosdevices").mkdir(parents = True)
    (prefix / "drive_c").mkdir()
    entry = commandoptions.CommandOptions()
    entry.set_is_wine_prefix(True)
    entry.set_prefix_dir(str(prefix))
    return entry


# rclone, installed or missing
@pytest.fixture
def rclone(monkeypatch):
    monkeypatch.setattr(programs, "is_tool_installed", lambda name: True)
    monkeypatch.setattr(programs, "get_tool_program", lambda name: "/tools/rclone")
    return "/tools/rclone"


@pytest.fixture
def no_rclone(monkeypatch):
    monkeypatch.setattr(programs, "is_tool_installed", lambda name: False)
    monkeypatch.setattr(programs, "get_tool_program", lambda name: None)


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(logger, "log_info", lambda *args, **kwargs: None)
    monkeypatch.setattr(logger, "log_error", lambda *args, **kwargs: None)
