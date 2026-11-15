# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import environment
from joybox import locker
from joybox import lockerinfo
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
