# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.tools import projectctr

ORDER = [
    ("CtrMakeRom", "windows"),
    ("CtrTool", "windows"),
    ("CtrMakeRom", "linux"),
    ("CtrTool", "linux"),
]


###########################################################
# Fakes
###########################################################

class Recorder:
    def __init__(self, results = None):
        self.calls = []
        self.results = list(results or [])

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return self.results.pop(0) if self.results else True


@pytest.fixture
def installed(monkeypatch):
    wanted = set(ORDER)
    monkeypatch.setattr(projectctr.programs, "should_program_be_installed", lambda name, platform: (name, platform) in wanted)
    monkeypatch.setattr(projectctr.programs, "get_program_install_dir", lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(projectctr.programs, "get_program_backup_dir", lambda name, platform: "/backup/%s/%s" % (name, platform))
    return wanted


###########################################################
# Config
###########################################################

def test_config_covers_both_programs():
    tool = projectctr.ProjectCTR()

    assert tool.get_name() == "ProjectCTR"
    tool_config = tool.get_config()
    assert tool_config["CtrMakeRom"]["program"]["linux"] == "CtrMakeRom/linux/makerom"
    assert tool_config["CtrTool"]["program"]["windows"] == "CtrTool/windows/ctrtool.exe"


###########################################################
# Setup
###########################################################

def test_setup_downloads_every_program(monkeypatch, installed):
    download = Recorder()
    monkeypatch.setattr(projectctr.release, "download_github_release", download)

    assert projectctr.ProjectCTR().setup()

    assert [(call["install_name"], call["install_dir"]) for call in download.calls] == [
        (name, "/install/%s/%s" % (name, platform)) for name, platform in ORDER]
    assert [call["search_file"] for call in download.calls] == ["makerom.exe", "ctrtool.exe", "makerom", "ctrtool"]
    assert download.calls[3]["chmod_files"] == [{"file": "ctrtool", "perms": 755}]


def test_setup_skips_programs_not_installed(monkeypatch, installed):
    installed.clear()
    download = Recorder()
    monkeypatch.setattr(projectctr.release, "download_github_release", download)

    assert projectctr.ProjectCTR().setup(config.SetupParams())
    assert download.calls == []


@pytest.mark.parametrize("failing", range(len(ORDER)))
def test_setup_stops_on_a_failed_download(monkeypatch, installed, failing):
    download = Recorder([True] * failing + [False])
    monkeypatch.setattr(projectctr.release, "download_github_release", download)

    assert not projectctr.ProjectCTR().setup()
    assert len(download.calls) == failing + 1


def test_setup_offline_installs_every_program(monkeypatch, installed):
    stored = Recorder()
    monkeypatch.setattr(projectctr.release, "setup_stored_release", stored)

    assert projectctr.ProjectCTR().setup_offline()

    assert [(call["install_name"], call["archive_dir"]) for call in stored.calls] == [
        (name, "/backup/%s/%s" % (name, platform)) for name, platform in ORDER]


def test_setup_offline_linux_matches_the_online_install(monkeypatch, installed):
    download = Recorder()
    stored = Recorder()
    monkeypatch.setattr(projectctr.release, "download_github_release", download)
    monkeypatch.setattr(projectctr.release, "setup_stored_release", stored)
    tool = projectctr.ProjectCTR()

    assert tool.setup()
    assert tool.setup_offline()

    # A stored archive must come out executable, like a fresh download
    keys = ["search_file", "install_files", "release_type", "chmod_files"]
    for online, offline in zip(download.calls[2:], stored.calls[2:], strict = True):
        assert {key: offline[key] for key in keys} == {key: online[key] for key in keys}


def test_setup_offline_skips_programs_not_installed(monkeypatch, installed):
    installed.clear()
    stored = Recorder()
    monkeypatch.setattr(projectctr.release, "setup_stored_release", stored)

    assert projectctr.ProjectCTR().setup_offline(config.SetupParams())
    assert stored.calls == []


@pytest.mark.parametrize("failing", range(len(ORDER)))
def test_setup_offline_stops_on_a_failed_install(monkeypatch, installed, failing):
    stored = Recorder([True] * failing + [False])
    monkeypatch.setattr(projectctr.release, "setup_stored_release", stored)

    assert not projectctr.ProjectCTR().setup_offline()
    assert len(stored.calls) == failing + 1
