# Imports
import pytest

# Local imports
from joybox import release


###########################################################
# Release selection
#
# Picks which downloadable artifact a tool installs from. Matching the wrong
# asset installs a source tarball, a debug build or another platform's binary,
# and the install then fails somewhere unrelated.
###########################################################

def asset(name):
    return {"name": name, "browser_download_url": "https://dl.example/" + name}


def release_with(*names):
    return {"assets": [asset(name) for name in names]}


@pytest.fixture
def github(monkeypatch):
    holder = {"json": None, "urls": []}

    def get_remote_json(url, **kwargs):
        holder["urls"].append(url)
        return holder["json"]

    monkeypatch.setattr(release.network, "get_remote_json", get_remote_json)
    monkeypatch.setattr(release.logger, "log_error", lambda *args, **kwargs: None)
    return holder


@pytest.fixture
def downloads(monkeypatch):
    calls = []
    monkeypatch.setattr(
        release, "download_general_release",
        lambda **kwargs: calls.append(kwargs) or True)
    return calls


def fetch(**kwargs):
    defaults = dict(
        github_user = "acme", github_repo = "tool",
        starts_with = "", ends_with = "",
        install_name = "Tool", install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.download_github_release(**defaults)


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
    ("skip_autobackup", True),
])
def test_every_install_option_is_passed_through(github, downloads, option, value):
    github["json"] = [release_with("tool.AppImage")]
    fetch(ends_with = ".AppImage", **{option: value})

    assert downloads[0][option] == value


###########################################################
# Webpage releases
###########################################################

@pytest.fixture
def webpage_url(monkeypatch):
    holder = {"url": None, "asked": []}

    def get_matching_url(**kwargs):
        holder["asked"].append(kwargs)
        return holder["url"]

    monkeypatch.setattr(release.webpage, "get_matching_url", get_matching_url)
    monkeypatch.setattr(release.logger, "log_error", lambda *args, **kwargs: None)
    return holder


def fetch_webpage(**kwargs):
    defaults = dict(
        webpage_url = "https://acme.example/downloads",
        webpage_base_url = "https://acme.example",
        starts_with = "", ends_with = "",
        install_name = "Tool", install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.download_webpage_release(**defaults)


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


###########################################################
# Source patches
#
# A patch entry either carries its content inline or names a file to read it
# from. An unreadable named file has to stop the build rather than silently
# apply nothing.
###########################################################

PATCH_BODY = "--- a/main.c\n+++ b/main.c\n"


def test_an_inline_patch_is_used_as_it_stands():
    entry = {"file": "fix.patch", "content": PATCH_BODY}

    assert release.resolve_patch_entry(entry) == ("fix.patch", PATCH_BODY)


def test_a_named_patch_file_is_read(tmp_path):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)

    name, content = release.resolve_patch_entry({"path": str(patch_path)})

    assert content == PATCH_BODY


def test_a_named_patch_file_supplies_the_filename(tmp_path):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)

    name, content = release.resolve_patch_entry({"path": str(patch_path)})

    assert name == "fix.patch"


def test_an_explicit_filename_wins_over_the_path(tmp_path):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)

    name, content = release.resolve_patch_entry(
        {"path": str(patch_path), "file": "renamed.patch"})

    assert name == "renamed.patch"


def test_a_named_patch_file_overrides_inline_content(tmp_path):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)

    name, content = release.resolve_patch_entry(
        {"path": str(patch_path), "content": "inline"})

    assert content == PATCH_BODY


def test_a_missing_patch_file_falls_back_to_inline_content(tmp_path):
    entry = {"path": str(tmp_path / "absent.patch"), "content": "inline", "file": "a.patch"}

    assert release.resolve_patch_entry(entry) == ("a.patch", "inline")


def test_an_unreadable_patch_file_resolves_to_nothing(tmp_path, monkeypatch):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)
    monkeypatch.setattr(release.serialization, "read_text_file", lambda *a, **k: None)

    assert release.resolve_patch_entry({"path": str(patch_path)}) == (None, None)


def test_an_empty_entry_resolves_to_empty_strings():
    assert release.resolve_patch_entry({}) == ("", "")
