# Imports
import json

# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox.tools import rclone

HETZNER_SECRET = "hetzner-secret"
GDRIVE_SECRET = "gdrive-secret"


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
    platforms = {"windows", "linux"}
    monkeypatch.setattr(rclone.programs, "should_program_be_installed", lambda name, platform: platform in platforms)
    monkeypatch.setattr(rclone.programs, "get_program_install_dir", lambda name, platform: "/install/%s/%s" % (name, platform))
    monkeypatch.setattr(rclone.programs, "get_program_backup_dir", lambda name, platform: "/backup/%s/%s" % (name, platform))
    return platforms


@pytest.fixture
def share_settings(monkeypatch):
    values = {}
    monkeypatch.setattr(rclone.settings, "get_value", lambda section, key, **kwargs: values.get(key))
    return values


@pytest.fixture
def written(monkeypatch, tmp_path):
    recorder = Recorder()
    monkeypatch.setattr(rclone.environment, "get_tools_root_dir", lambda: str(tmp_path))
    monkeypatch.setattr(rclone.fileops, "touch_file", recorder)
    return recorder


###########################################################
# Config
###########################################################

def test_config_names_both_platforms():
    tool = rclone.RClone()

    assert tool.get_name() == "RClone"
    entry = tool.get_config()["RClone"]
    assert entry["program"]["linux"] == "RClone/linux/rclone"
    assert entry["config_file"]["windows"] == "RClone/windows/rclone.conf"
    assert entry["run_sandboxed"] == {"windows": False, "linux": False}


###########################################################
# Setup
###########################################################

def test_setup_downloads_each_platform(monkeypatch, installed):
    download = Recorder()
    monkeypatch.setattr(rclone.release, "download_general_release", download)

    assert rclone.RClone().setup()

    assert [call["search_file"] for call in download.calls] == ["rclone.exe", "rclone"]
    assert download.calls[1]["install_dir"] == "/install/RClone/linux"
    assert download.calls[1]["archive_url"].endswith("linux-amd64.zip")


def test_setup_skips_platforms_not_installed(monkeypatch, installed):
    installed.clear()
    download = Recorder()
    monkeypatch.setattr(rclone.release, "download_general_release", download)

    assert rclone.RClone().setup(config.SetupParams())
    assert download.calls == []


@pytest.mark.parametrize("results", [[False], [True, False]])
def test_setup_stops_on_a_failed_download(monkeypatch, installed, results):
    download = Recorder(results)
    monkeypatch.setattr(rclone.release, "download_general_release", download)

    assert not rclone.RClone().setup()
    assert len(download.calls) == len(results)


def test_setup_offline_finds_the_binary_on_each_platform(monkeypatch, installed):
    stored = Recorder()
    monkeypatch.setattr(rclone.release, "setup_stored_release", stored)

    assert rclone.RClone().setup_offline()

    # The release zip nests the binary under a versioned folder
    assert [call["search_file"] for call in stored.calls] == ["rclone.exe", "rclone"]
    assert [call["archive_dir"] for call in stored.calls] == ["/backup/RClone/windows", "/backup/RClone/linux"]


def test_setup_offline_skips_platforms_not_installed(monkeypatch, installed):
    installed.clear()
    stored = Recorder()
    monkeypatch.setattr(rclone.release, "setup_stored_release", stored)

    assert rclone.RClone().setup_offline(config.SetupParams())
    assert stored.calls == []


@pytest.mark.parametrize("results", [[False], [True, False]])
def test_setup_offline_stops_on_a_failed_install(monkeypatch, installed, results):
    stored = Recorder(results)
    monkeypatch.setattr(rclone.release, "setup_stored_release", stored)

    assert not rclone.RClone().setup_offline()
    assert len(stored.calls) == len(results)


###########################################################
# Configure
###########################################################

def set_gdrive(values):
    values.update({
        "locker_gdrive_name": "gdrive",
        "locker_gdrive_type": "drive",
        "locker_gdrive_token": GDRIVE_SECRET,
    })


def set_hetzner(values, **overrides):
    remote = {"host": "box.example", "user": "u1", "pass": HETZNER_SECRET}
    remote.update(overrides)
    values.update({
        "locker_hetzner_name": "hetzner",
        "locker_hetzner_type": "sftp",
        "locker_hetzner_config": json.dumps(remote),
    })


def test_configure_writes_both_remotes_to_both_platforms(share_settings, written, tmp_path):
    set_gdrive(share_settings)
    set_hetzner(share_settings)

    assert rclone.RClone().configure()

    assert [call["src"] for call in written.calls] == [
        str(tmp_path / "RClone/windows/rclone.conf"),
        str(tmp_path / "RClone/linux/rclone.conf"),
    ]
    contents = written.calls[0]["contents"]
    assert contents.startswith("[gdrive]\ntype = drive\n")
    assert "token = %s" % GDRIVE_SECRET in contents
    assert "\n\n[hetzner]\ntype = sftp\nhost = box.example\nuser = u1\npass = %s\n" % HETZNER_SECRET in contents
    assert contents == written.calls[1]["contents"]
    assert "GDRIVE_" not in contents and "HETZNER_" not in contents


def test_configure_without_credentials_writes_empty_files(share_settings, written):
    assert rclone.RClone().configure(config.SetupParams())

    assert [call["contents"] for call in written.calls] == ["", ""]


def test_configure_omits_a_partial_gdrive_remote(share_settings, written):
    set_gdrive(share_settings)
    share_settings["locker_gdrive_token"] = None
    set_hetzner(share_settings)

    assert rclone.RClone().configure()

    assert written.calls[0]["contents"].startswith("[hetzner]")


def test_configure_omits_a_hetzner_remote_missing_its_password(share_settings, written):
    set_hetzner(share_settings, **{"pass": ""})

    assert rclone.RClone().configure()

    assert written.calls[0]["contents"] == ""


@pytest.mark.parametrize("raw", ["{not json", "[1, 2]", "\"box.example\""])
def test_configure_ignores_a_hetzner_config_that_is_not_an_object(share_settings, written, raw):
    set_gdrive(share_settings)
    set_hetzner(share_settings)
    share_settings["locker_hetzner_config"] = raw

    assert rclone.RClone().configure()

    contents = written.calls[0]["contents"]
    assert contents.startswith("[gdrive]")
    assert "[hetzner]" not in contents


def test_configure_stops_when_a_file_cannot_be_written(share_settings, written):
    written.results = [False]

    assert not rclone.RClone().configure()
    assert len(written.calls) == 1
