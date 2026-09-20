# Imports
import os

# Third-party imports
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


###########################################################
# Installing a release
#
# Turns a downloaded archive into an installed tool. The install directory is
# what every later lookup resolves against, so a release that unpacks to the
# wrong layout breaks the tool rather than the install.
###########################################################

def write(path, contents = "data"):
    path = str(path)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "w") as handle:
        handle.write(contents)
    return path


def tree(root):
    found = []
    for directory, _, filenames in os.walk(str(root)):
        for filename in filenames:
            found.append(os.path.relpath(os.path.join(directory, filename), str(root)))
    return sorted(found)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    # The archive, the scratch directory it unpacks into, and the install
    # target, with the extractor standing in for a real 7-Zip run.
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    install_dir = tmp_path / "install"
    payload = {"files": ["tool.sh", os.path.join("data", "assets.bin")]}

    monkeypatch.setattr(
        release.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))

    def extract_archive(archive_file, extract_dir, **kwargs):
        for relative in payload["files"]:
            write(os.path.join(extract_dir, relative), "unpacked")
        return True

    monkeypatch.setattr(release.archive, "extract_archive", extract_archive)
    monkeypatch.setattr(release.logger, "log_error", lambda *args, **kwargs: None)

    return {
        "root": tmp_path,
        "scratch": str(scratch),
        "install_dir": str(install_dir),
        "payload": payload,
    }


def setup_archive(workspace, archive_name = "Tool-1.0.zip", **kwargs):
    archive_file = write(os.path.join(str(workspace["root"]), "downloads", archive_name))
    defaults = dict(
        archive_file = archive_file,
        install_name = "Tool",
        install_dir = workspace["install_dir"])
    defaults.update(kwargs)
    return release.setup_general_release(**defaults)


###########################################################
# Archive releases
###########################################################

def test_an_archive_release_is_unpacked_into_the_install_directory(workspace):
    assert setup_archive(workspace) is True
    assert tree(workspace["install_dir"]) == [os.path.join("data", "assets.bin"), "tool.sh"]


def test_the_install_directory_is_created(workspace):
    setup_archive(workspace)

    assert os.path.isdir(workspace["install_dir"])


def test_only_the_named_files_are_installed(workspace):
    # A release that ships documentation and sources alongside the binary
    # should not have all of it copied into the tools directory.
    assert setup_archive(workspace, install_files = ["tool.sh"]) is True
    assert tree(workspace["install_dir"]) == ["tool.sh"]


def test_a_named_file_keeps_its_own_path(workspace):
    assert setup_archive(
        workspace, install_files = [os.path.join("data", "assets.bin")]) is True
    assert tree(workspace["install_dir"]) == [os.path.join("data", "assets.bin")]


def test_the_search_directory_follows_the_file_it_was_told_to_find(workspace):
    # Archives usually unpack into a single versioned directory, and the
    # contents of that directory are what should be installed.
    workspace["payload"]["files"] = [
        os.path.join("Tool-1.0", "tool.sh"),
        os.path.join("Tool-1.0", "data", "assets.bin"),
    ]

    assert setup_archive(workspace, search_file = "tool.sh") is True
    assert tree(workspace["install_dir"]) == [os.path.join("data", "assets.bin"), "tool.sh"]


def test_a_search_file_that_is_not_there_leaves_the_layout_alone(workspace):
    assert setup_archive(workspace, search_file = "absent.sh") is True
    assert "tool.sh" in tree(workspace["install_dir"])


def test_an_archive_that_will_not_extract_installs_nothing(workspace, monkeypatch):
    monkeypatch.setattr(release.archive, "extract_archive", lambda **kwargs: False)

    assert setup_archive(workspace) is False


def test_an_install_that_produced_nothing_reports_failure(workspace):
    workspace["payload"]["files"] = []

    assert setup_archive(workspace) is False


def test_an_unknown_release_type_installs_nothing(workspace):
    # The type decides whether the file is unpacked or copied, and guessing
    # wrong would copy an archive into place as if it were the program.
    assert setup_archive(workspace, archive_name = "Tool-1.0.bin") is False


def test_the_scratch_directory_is_cleaned_up(workspace):
    setup_archive(workspace)

    assert tree(workspace["scratch"]) == []


def test_a_release_without_a_scratch_directory_installs_nothing(workspace, monkeypatch):
    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert setup_archive(workspace) is False


###########################################################
# Standalone programs
###########################################################

def test_an_appimage_is_installed_under_the_install_name(workspace):
    # AppImages are published with a version in the filename, and every tool
    # lookup expects a stable name.
    assert setup_archive(workspace, archive_name = "Tool-1.0.AppImage") is True
    assert tree(workspace["install_dir"]) == ["Tool.AppImage"]


def test_an_installed_appimage_can_be_run(workspace):
    import stat

    setup_archive(workspace, archive_name = "Tool-1.0.AppImage")
    installed = os.path.join(workspace["install_dir"], "Tool.AppImage")

    assert bool(os.stat(installed).st_mode & stat.S_IXUSR)


def test_a_plain_program_is_installed_from_beside_the_archive(workspace):
    # An installer executable is not unpacked, so what gets installed is what
    # sits next to it rather than anything in the scratch directory.
    write(os.path.join(str(workspace["root"]), "downloads", "readme.txt"), "notes")

    assert setup_archive(workspace, archive_name = "Tool-1.0.exe") is True
    assert "readme.txt" in tree(workspace["install_dir"])


def test_a_program_release_does_not_extract_anything(workspace, monkeypatch):
    def fail(**kwargs):
        raise AssertionError("a standalone program is not an archive")

    monkeypatch.setattr(release.archive, "extract_archive", fail)

    setup_archive(workspace, archive_name = "Tool-1.0.AppImage")


###########################################################
# Post-install fixups
###########################################################

def test_a_named_file_is_made_executable(workspace):
    import stat

    setup_archive(
        workspace,
        chmod_files = [{"file": "tool.sh", "perms": 755}])
    installed = os.path.join(workspace["install_dir"], "tool.sh")

    assert bool(os.stat(installed).st_mode & stat.S_IXUSR)


def test_a_file_that_was_not_named_keeps_its_permissions(workspace):
    import stat

    setup_archive(
        workspace,
        chmod_files = [{"file": "tool.sh", "perms": 755}])
    other = os.path.join(workspace["install_dir"], "data", "assets.bin")

    assert not bool(os.stat(other).st_mode & stat.S_IXUSR)


def test_a_release_file_is_renamed_to_what_the_tool_expects(workspace):
    # Releases rename their binary between versions; the tool registry looks
    # for one name.
    workspace["payload"]["files"] = ["tool-1.0.sh"]

    setup_archive(
        workspace,
        rename_files = [{"from": "tool-1.0.sh", "to": "tool.sh", "ratio": 90}])

    assert tree(workspace["install_dir"]) == ["tool.sh"]


def test_a_file_that_is_not_similar_enough_is_left_alone(workspace):
    workspace["payload"]["files"] = ["unrelated.bin"]

    setup_archive(
        workspace,
        rename_files = [{"from": "tool.sh", "to": "renamed.sh", "ratio": 90}])

    assert tree(workspace["install_dir"]) == ["unrelated.bin"]


###########################################################
# Backing up the archive
###########################################################

@pytest.fixture
def backups(monkeypatch):
    calls = []
    monkeypatch.setattr(
        release.locker, "convert_to_relative_path", lambda path: "relative/" + os.path.basename(path))
    monkeypatch.setattr(
        release.locker, "backup",
        lambda src, dest_rel_path, **kwargs: calls.append((src, dest_rel_path)) or True)
    return calls


def test_the_archive_is_backed_up_to_the_locker(workspace, backups):
    setup_archive(workspace, backups_dir = "/locker/tools")

    assert backups[0][1] == "relative/Tool-1.0.zip"


def test_the_backup_can_be_skipped(workspace, backups):
    setup_archive(workspace, backups_dir = "/locker/tools", skip_autobackup = True)

    assert backups == []


def test_nothing_is_backed_up_without_a_destination(workspace, backups):
    setup_archive(workspace)

    assert backups == []


def test_a_failed_backup_fails_the_install(workspace, monkeypatch):
    monkeypatch.setattr(release.locker, "convert_to_relative_path", lambda path: "relative/x")
    monkeypatch.setattr(release.locker, "backup", lambda **kwargs: False)

    assert setup_archive(workspace, backups_dir = "/locker/tools") is False


###########################################################
# Installing from stored archives
###########################################################

@pytest.fixture
def stored(monkeypatch, tmp_path):
    # Records which archive the selection settled on.
    calls = []
    monkeypatch.setattr(
        release, "setup_general_release",
        lambda **kwargs: calls.append(kwargs) or True)
    monkeypatch.setattr(release.logger, "log_error", lambda *args, **kwargs: None)
    monkeypatch.setattr(release.logger, "log_warning", lambda *args, **kwargs: None)
    return calls


def install_stored(archive_dir, **kwargs):
    defaults = dict(
        archive_dir = str(archive_dir),
        install_name = "Tool",
        install_dir = "/tools/Tool")
    defaults.update(kwargs)
    return release.setup_stored_release(**defaults)


def test_the_newest_stored_archive_is_used(stored, tmp_path):
    # The list is sorted by name, so the last entry is the highest version.
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    write(archives / "Tool-2.0.zip")

    assert install_stored(archives) is True
    assert stored[0]["archive_file"].endswith("Tool-2.0.zip")


def test_the_oldest_stored_archive_can_be_asked_for(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")
    write(archives / "Tool-2.0.zip")

    install_stored(archives, use_first_found = True)

    assert stored[0]["archive_file"].endswith("Tool-1.0.zip")


def test_a_preferred_archive_is_chosen_by_name(stored, tmp_path):
    # Some tools ship one archive per platform in the same directory.
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0-linux.zip")
    write(archives / "Tool-1.0-windows.zip")

    install_stored(archives, preferred_archive = "linux")

    assert stored[0]["archive_file"].endswith("Tool-1.0-linux.zip")


def test_a_preferred_archive_that_is_not_there_installs_nothing(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0-windows.zip")

    assert install_stored(archives, preferred_archive = "linux") is False
    assert stored == []


def test_an_empty_archive_directory_installs_nothing(stored, tmp_path):
    archives = tmp_path / "archives"
    archives.mkdir()

    assert install_stored(archives) is False
    assert stored == []


def test_a_missing_archive_directory_installs_nothing(stored, tmp_path):
    assert install_stored(tmp_path / "absent") is False
    assert stored == []


def test_a_missing_archive_can_be_skipped_quietly(stored, tmp_path):
    # The locker holds these archives, and a machine that has not downloaded
    # it yet should still finish setting itself up.
    assert install_stored(tmp_path / "absent", skip_if_missing = True) is True
    assert stored == []


def test_a_directory_holding_no_archives_can_be_skipped_quietly(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "notes.txt")

    assert install_stored(archives, skip_if_missing = True) is True
    assert stored == []


def test_a_real_archive_is_not_skipped(stored, tmp_path):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    assert install_stored(archives, skip_if_missing = True) is True
    assert len(stored) == 1


@pytest.mark.parametrize("option,value", [
    ("search_file", "tool.sh"),
    ("install_files", ["tool.sh"]),
    ("chmod_files", [{"file": "tool.sh", "perms": 755}]),
    ("rename_files", [{"from": "a", "to": "b", "ratio": 90}]),
    ("installer_type", "inno"),
    ("release_type", "Archive"),
])
def test_every_stored_install_option_is_passed_through(stored, tmp_path, option, value):
    archives = tmp_path / "archives"
    write(archives / "Tool-1.0.zip")

    install_stored(archives, **{option: value})

    assert stored[0][option] == value


###########################################################
# Downloading a release
###########################################################

@pytest.fixture
def remote(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {"downloaded": [], "installs": [], "download_ok": True, "scratch": str(scratch)}

    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(
        release.network, "download_url",
        lambda url, **kwargs: state["downloaded"].append((url, kwargs)) or state["download_ok"])
    monkeypatch.setattr(
        release, "setup_general_release",
        lambda **kwargs: state["installs"].append(kwargs) or True)
    monkeypatch.setattr(release.logger, "log_error", lambda *args, **kwargs: None)
    return state


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
