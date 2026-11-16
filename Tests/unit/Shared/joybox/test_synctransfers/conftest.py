# Third-party imports
import pytest

# Local imports
from joybox import fileops
from sync_helpers import FakeRemote


@pytest.fixture
def remote(monkeypatch, tmp_path):
    return FakeRemote(monkeypatch, tmp_path / "remote.db")


@pytest.fixture
def temp_dirs(monkeypatch, tmp_path):
    # Every temporary directory handed out, so cleanup can be checked
    created = []
    original = fileops.create_temporary_directory

    def create(**kwargs):
        result = original(directory = str(tmp_path / "temps"))
        created.append(result[1])
        return result

    monkeypatch.setattr(fileops, "create_temporary_directory", create)
    return created
