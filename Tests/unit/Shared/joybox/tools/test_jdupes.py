# Third-party imports
import pytest

# Local imports
from joybox.tools import jdupes

KEYS = ["search_file", "install_files", "installer_type", "release_type", "chmod_files", "rename_files"]


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return True


@pytest.fixture
def releases(monkeypatch):
    for name in ["should_program_be_installed", "should_library_be_installed"]:
        monkeypatch.setattr(jdupes.programs, name, lambda *args: True)
    for name in ["get_program_install_dir", "get_library_install_dir"]:
        monkeypatch.setattr(jdupes.programs, name, lambda name, platform: "/install/%s/%s" % (name, platform))
    for name in ["get_program_backup_dir", "get_library_backup_dir"]:
        monkeypatch.setattr(jdupes.programs, name, lambda name, platform: "/backup/%s/%s" % (name, platform))
    online = Recorder()
    stored = Recorder()
    monkeypatch.setattr(jdupes.release, "download_github_release", online)
    monkeypatch.setattr(jdupes.release, "setup_stored_release", stored)
    return online, stored


def test_setup_offline_matches_the_online_install(releases):
    online, stored = releases
    tool = jdupes.JDupes()

    assert tool.setup()
    assert tool.setup_offline()

    # The linux package nests the binary under usr/bin
    offline = {call["install_dir"]: call for call in stored.calls}
    assert online.calls
    for call in online.calls:
        expected = {key: call[key] for key in KEYS if key in call}
        assert {key: offline[call["install_dir"]].get(key) for key in expected} == expected
