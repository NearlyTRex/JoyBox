# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, environment, gameinfo

# Helpers beside this file are imported by name, so this directory has to be
# importable; appended so the suite's top level conftest is not shadowed.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def tree(tmp_path, monkeypatch):
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
        gameinfo.lockerinfo, "get_primary_remote_locker_type", lambda: config.LockerType.LOCAL)
    return roots


@pytest.fixture
def game(tree):
    from gameinfo_helpers import write_game
    return gameinfo.GameInfo(json_file = write_game(tree))
