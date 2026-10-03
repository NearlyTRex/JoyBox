# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import release


###########################################################
# Downloading a release
###########################################################

def test_a_release_is_downloaded_before_it_is_installed(remote):
    assert release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool") is True
    assert remote["downloaded"][0][0] == "https://dl.example/Tool-1.0.zip"


def test_a_downloaded_release_keeps_its_filename(remote):
    # The extension is what decides whether the release is unpacked or copied.
    release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool")

    assert remote["installs"][0]["archive_file"] == \
        os.path.join(remote["scratch"], "Tool-1.0.zip")


def test_a_release_that_will_not_download_is_not_installed(remote):
    remote["download_ok"] = False

    assert release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool") is False
    assert remote["installs"] == []


def test_the_download_lands_where_the_install_reads_it(remote):
    release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool")
    downloaded = remote["downloaded"][0][1]

    assert downloaded["output_file"] == remote["installs"][0]["archive_file"]
    assert "output_dir" not in downloaded


def test_the_install_result_is_returned(remote):
    remote["install_ok"] = False

    assert release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool") is False


@pytest.mark.parametrize("download_ok,install_ok", [(True, True), (False, True), (True, False)])
def test_the_download_directory_is_always_removed(remote, download_ok, install_ok):
    remote["download_ok"] = download_ok
    remote["install_ok"] = install_ok
    with open(os.path.join(remote["scratch"], "Tool-1.0.zip"), "w") as handle:
        handle.write("archive")

    release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool")

    assert not os.path.exists(remote["scratch"])


def test_a_release_without_a_download_directory_is_not_installed(remote, monkeypatch):
    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool") is False
    assert remote["downloaded"] == []


@pytest.mark.parametrize("option,value", [
    ("search_file", "bin/tool"),
    ("backups_dir", "/locker/Programs"),
    ("install_files", ["tool"]),
    ("chmod_files", [{"file": "tool", "perms": 755}]),
    ("rename_files", [{"from": "a", "to": "b", "ratio": 90}]),
    ("release_type", "Archive"),
    ("locker_type", "Remote"),
    ("skip_autobackup", True),
    ("verbose", True),
    ("pretend_run", True),
    ("exit_on_failure", True),
])
def test_every_download_option_reaches_the_install(remote, option, value):
    release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool",
        **{option: value})

    assert remote["installs"][0][option] == value


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_download(remote, flag):
    release.download_general_release(
        archive_url = "https://dl.example/Tool-1.0.zip",
        install_name = "Tool",
        install_dir = "/tools/Tool",
        **{flag: True})

    assert remote["downloaded"][0][1][flag] is True
