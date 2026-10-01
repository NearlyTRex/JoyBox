# Imports

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import fetch, fetch_webpage, release_with


###########################################################
# Release selection
#
# Picks which downloadable artifact a tool installs from. Matching the wrong
# asset installs a source tarball, a debug build or another platform's binary,
# and the install then fails somewhere unrelated.
###########################################################

###########################################################
# Matching an asset
###########################################################

def test_an_asset_matching_both_ends_is_chosen(github, downloads):
    github["json"] = [release_with("tool-1.2-linux.AppImage", "tool-1.2-windows.exe")]

    assert fetch(starts_with = "tool-", ends_with = ".AppImage") is True
    assert downloads[0]["archive_url"].endswith("tool-1.2-linux.AppImage")


def test_a_prefix_alone_is_enough(github, downloads):
    github["json"] = [release_with("other.zip", "tool-1.2.zip")]
    fetch(starts_with = "tool-")

    assert downloads[0]["archive_url"].endswith("tool-1.2.zip")


def test_a_suffix_alone_is_enough(github, downloads):
    github["json"] = [release_with("tool.zip", "tool.AppImage")]
    fetch(ends_with = ".AppImage")

    assert downloads[0]["archive_url"].endswith("tool.AppImage")


def test_the_wrong_platform_is_not_chosen(github, downloads):
    # Every release carries builds for platforms this host cannot run.
    github["json"] = [release_with("tool-windows.exe", "tool-linux.AppImage")]
    fetch(ends_with = ".AppImage")

    assert "windows" not in downloads[0]["archive_url"]


def test_the_first_match_wins(github, downloads):
    github["json"] = [release_with("tool-a.AppImage", "tool-b.AppImage")]
    fetch(ends_with = ".AppImage")

    assert downloads[0]["archive_url"].endswith("tool-a.AppImage")


def test_an_earlier_release_is_preferred(github, downloads):
    # The api lists newest first, so the first release holding a match wins.
    github["json"] = [release_with("tool-2.0.AppImage"), release_with("tool-1.0.AppImage")]
    fetch(ends_with = ".AppImage")

    assert downloads[0]["archive_url"].endswith("tool-2.0.AppImage")


def test_a_later_release_is_used_when_the_first_has_no_match(github, downloads):
    github["json"] = [release_with("tool-2.0.zip"), release_with("tool-1.0.AppImage")]
    fetch(ends_with = ".AppImage")

    assert downloads[0]["archive_url"].endswith("tool-1.0.AppImage")


def test_no_matching_asset_installs_nothing(github, downloads):
    github["json"] = [release_with("tool.zip", "tool.tar.gz")]

    assert fetch(ends_with = ".AppImage") is False
    assert downloads == []


def test_a_release_without_assets_is_skipped(github, downloads):
    github["json"] = [{"tag_name": "v1.0"}, release_with("tool.AppImage")]
    fetch(ends_with = ".AppImage")

    assert downloads[0]["archive_url"].endswith("tool.AppImage")


def test_an_empty_asset_list_matches_nothing(github, downloads):
    github["json"] = [{"assets": []}]

    assert fetch(ends_with = ".AppImage") is False


def test_no_match_terms_match_nothing(github, downloads):
    # Without a prefix or suffix every asset would match, including sources.
    github["json"] = [release_with("tool.zip")]

    assert fetch() is False
    assert downloads == []


def test_missing_match_terms_are_treated_as_empty(github, downloads):
    github["json"] = [release_with("tool.zip", "tool.AppImage")]

    assert fetch(starts_with = None, ends_with = ".AppImage") is True
    assert downloads[0]["archive_url"].endswith("tool.AppImage")


###########################################################
# Malformed api responses
###########################################################

def test_an_api_error_object_installs_nothing(github, downloads):
    github["json"] = {"message": "Not Found"}

    assert fetch(ends_with = ".AppImage", get_latest = True) is False
    assert downloads == []


@pytest.mark.parametrize("entry", [
    "v1.0",
    None,
    {"assets": None},
    {"assets": "tool.AppImage"},
    {"assets": ["tool.AppImage"]},
    {"assets": [{"browser_download_url": "https://dl.example/tool.AppImage"}]},
    {"assets": [{"name": "tool.AppImage"}]},
    {"assets": [{"name": "tool.AppImage", "browser_download_url": None}]},
    {"assets": [{"name": None, "browser_download_url": "https://dl.example/x"}]},
])
def test_a_malformed_release_entry_is_skipped(github, downloads, entry):
    github["json"] = [entry, release_with("tool.AppImage")]

    assert fetch(ends_with = ".AppImage") is True
    assert downloads[0]["archive_url"] == "https://dl.example/tool.AppImage"


def test_only_malformed_entries_install_nothing(github, downloads):
    github["json"] = ["v1.0", {"assets": None}]

    assert fetch(ends_with = ".AppImage") is False


###########################################################
# The api call
###########################################################

def test_the_releases_endpoint_is_used(github, downloads):
    github["json"] = [release_with("tool.AppImage")]
    fetch(ends_with = ".AppImage")

    assert github["urls"][0] == "https://api.github.com/repos/acme/tool/releases"


def test_the_latest_endpoint_is_used_when_asked(github, downloads):
    github["json"] = release_with("tool.AppImage")
    fetch(ends_with = ".AppImage", get_latest = True)

    assert github["urls"][0].endswith("/releases/latest")


def test_a_single_release_object_is_accepted(github, downloads):
    # The latest endpoint returns one object rather than a list.
    github["json"] = release_with("tool.AppImage")

    assert fetch(ends_with = ".AppImage", get_latest = True) is True
    assert downloads[0]["archive_url"].endswith("tool.AppImage")


def test_no_release_information_installs_nothing(github, downloads):
    github["json"] = None

    assert fetch(ends_with = ".AppImage") is False
    assert downloads == []


def test_an_empty_release_list_installs_nothing(github, downloads):
    github["json"] = []

    assert fetch(ends_with = ".AppImage") is False


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_api_call_and_the_download(github, downloads, monkeypatch, flag):
    asked = []
    monkeypatch.setattr(
        release.network, "get_remote_json",
        lambda url, **kwargs: asked.append(kwargs) or [release_with("tool.AppImage")])
    fetch(ends_with = ".AppImage", **{flag: True})

    assert asked[0][flag] is True
    assert downloads[0][flag] is True


###########################################################
# Options passed through
###########################################################

def test_the_install_target_is_passed_through(github, downloads):
    github["json"] = [release_with("tool.AppImage")]
    fetch(ends_with = ".AppImage", install_name = "MyTool", install_dir = "/tools/MyTool")

    assert downloads[0]["install_name"] == "MyTool"
    assert downloads[0]["install_dir"] == "/tools/MyTool"


@pytest.mark.parametrize("option,value", [
    ("search_file", "bin/tool"),
    ("backups_dir", "/locker/Programs"),
    ("install_files", ["tool"]),
    ("chmod_files", [{"file": "tool", "perms": "755"}]),
    ("rename_files", [{"from": "a", "to": "b"}]),
    ("installer_type", "inno"),
    ("release_type", "Archive"),
    ("locker_type", "Remote"),
    ("skip_autobackup", True),
])
def test_every_install_option_is_passed_through(github, downloads, option, value):
    github["json"] = [release_with("tool.AppImage")]
    fetch(ends_with = ".AppImage", **{option: value})

    assert downloads[0][option] == value


###########################################################
# Webpage releases
###########################################################

def test_a_scraped_url_is_downloaded(webpage_url, downloads):
    webpage_url["url"] = "https://acme.example/tool-1.2.AppImage"

    assert fetch_webpage(ends_with = ".AppImage") is True
    assert downloads[0]["archive_url"] == "https://acme.example/tool-1.2.AppImage"


def test_the_match_terms_reach_the_scraper(webpage_url, downloads):
    webpage_url["url"] = "https://acme.example/tool.AppImage"
    fetch_webpage(starts_with = "tool-", ends_with = ".AppImage", get_latest = True)
    asked = webpage_url["asked"][0]

    assert asked["starts_with"] == "tool-"
    assert asked["ends_with"] == ".AppImage"
    assert asked["get_latest"] is True


def test_the_base_url_reaches_the_scraper(webpage_url, downloads):
    # Relative links on the page are resolved against it.
    webpage_url["url"] = "https://acme.example/tool.AppImage"
    fetch_webpage(ends_with = ".AppImage")

    assert webpage_url["asked"][0]["base_url"] == "https://acme.example"


def test_no_scraped_url_installs_nothing(webpage_url, downloads):
    webpage_url["url"] = None

    assert fetch_webpage(ends_with = ".AppImage") is False
    assert downloads == []


def test_webpage_install_options_are_passed_through(webpage_url, downloads):
    webpage_url["url"] = "https://acme.example/tool.AppImage"
    fetch_webpage(ends_with = ".AppImage", install_files = ["tool"], installer_type = "inno")

    assert downloads[0]["install_files"] == ["tool"]
    assert downloads[0]["installer_type"] == "inno"


@pytest.mark.parametrize("option,value", [
    ("search_file", "bin/tool"),
    ("backups_dir", "/locker/Programs"),
    ("chmod_files", [{"file": "tool", "perms": "755"}]),
    ("rename_files", [{"from": "a", "to": "b"}]),
    ("release_type", "Program"),
    ("locker_type", "Remote"),
    ("skip_autobackup", True),
])
def test_every_webpage_install_option_is_passed_through(webpage_url, downloads, option, value):
    webpage_url["url"] = "https://acme.example/tool.AppImage"
    fetch_webpage(ends_with = ".AppImage", **{option: value})

    assert downloads[0][option] == value


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_scraper_and_the_download(webpage_url, downloads, flag):
    webpage_url["url"] = "https://acme.example/tool.AppImage"
    fetch_webpage(ends_with = ".AppImage", **{flag: True})

    assert webpage_url["asked"][0][flag] is True
    assert downloads[0][flag] is True

