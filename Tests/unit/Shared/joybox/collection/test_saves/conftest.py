# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox.collection import saves

sys.path.append(os.path.dirname(__file__))


@pytest.fixture
def fake_archive(monkeypatch):
    from saves_helpers import FakeArchive
    fake = FakeArchive()
    monkeypatch.setattr(saves, "archive", fake)
    return fake


@pytest.fixture
def fake_locker(monkeypatch):
    from saves_helpers import FakeLocker
    fake = FakeLocker()
    monkeypatch.setattr(saves, "locker", fake)
    return fake


@pytest.fixture
def fake_hashing(monkeypatch):
    from saves_helpers import FakeHashing
    fake = FakeHashing()
    monkeypatch.setattr(saves, "hashing", fake)
    return fake


@pytest.fixture
def temp_dirs(tmp_path, monkeypatch):
    # Every temporary directory handed out, so a test can check it was removed.
    created = []
    root = tmp_path / "tmp"
    root.mkdir()

    def create_temporary_directory(verbose = False, pretend_run = False):
        if pretend_run:
            path = str(root / "pretend")
        else:
            path = str(root / ("dir%d" % len(created)))
            os.mkdir(path)
        created.append(path)
        return (True, path)

    monkeypatch.setattr(saves.fileops, "create_temporary_directory", create_temporary_directory)
    return created


@pytest.fixture
def game(tmp_path, isolated_settings, fake_archive, fake_locker, fake_hashing, temp_dirs):
    from saves_helpers import FakeGameInfo
    live = tmp_path / "live"
    packed = tmp_path / "packed"
    live.mkdir()
    (live / "slot1.sav").write_bytes(b"save slot one")
    return FakeGameInfo(str(live), str(packed))
