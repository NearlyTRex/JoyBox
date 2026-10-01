# Imports
import os
import stat

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import failing, setup_archive, tree, write


###########################################################
# Installing a release
#
# Turns a downloaded archive into an installed tool. The install directory is
# what every later lookup resolves against, so a release that unpacks to the
# wrong layout breaks the tool rather than the install.
###########################################################

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
    setup_archive(
        workspace,
        chmod_files = [{"file": "tool.sh", "perms": 755}])
    installed = os.path.join(workspace["install_dir"], "tool.sh")

    assert bool(os.stat(installed).st_mode & stat.S_IXUSR)


def test_a_file_that_was_not_named_keeps_its_permissions(workspace):
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


def test_the_backup_goes_to_the_requested_locker(workspace, backups):
    setup_archive(workspace, backups_dir = "/locker/tools", locker_type = "Remote")

    assert backups[0][0].endswith("Tool-1.0.zip")
    assert backups[0][2]["locker_type"] == "Remote"


###########################################################
# Release type
###########################################################

def test_a_rar_release_is_unpacked_like_any_other_archive(workspace):
    assert setup_archive(workspace, archive_name = "Tool-1.0.rar") is True
    assert workspace["payload"]["extracted"][0].endswith("Tool-1.0.rar")


def test_a_tarball_release_is_unpacked(workspace):
    assert setup_archive(workspace, archive_name = "Tool-1.0.tar.gz") is True
    assert "tool.sh" in tree(workspace["install_dir"])


def test_an_explicit_archive_type_unpacks_an_unrecognised_file(workspace):
    assert setup_archive(
        workspace, archive_name = "Tool-1.0.bin",
        release_type = release.config.ReleaseType.ARCHIVE) is True
    assert "tool.sh" in tree(workspace["install_dir"])


def test_an_explicit_program_type_copies_an_unrecognised_file(workspace):
    assert setup_archive(
        workspace, archive_name = "Tool-1.0.bin",
        release_type = release.config.ReleaseType.PROGRAM) is True
    assert tree(workspace["install_dir"]) == ["Tool-1.0.bin"]
    assert workspace["payload"]["extracted"] == []


###########################################################
# Failures
#
# Every failed step fails the install and still removes the scratch
# directory the release was unpacked into.
###########################################################

@pytest.mark.parametrize("target,archive_name,options", [
    ("make_directory", "Tool-1.0.zip", {}),
    ("smart_copy", "Tool-1.0.AppImage", {}),
    ("mark_as_executable", "Tool-1.0.AppImage", {}),
    ("smart_copy", "Tool-1.0.zip", {"install_files": ["tool.sh"]}),
    ("copy_contents", "Tool-1.0.zip", {}),
    ("chmod_file_or_directory", "Tool-1.0.zip", {"chmod_files": [{"file": "tool.sh", "perms": 755}]}),
    ("smart_move", "Tool-1.0.zip", {"rename_files": [{"from": "tool.sh", "to": "t.sh", "ratio": 90}]}),
])
def test_a_failed_step_fails_the_install(workspace, monkeypatch, target, archive_name, options):
    monkeypatch.setattr(release.fileops, target, failing)

    assert setup_archive(workspace, archive_name = archive_name, **options) is False


@pytest.mark.parametrize("target,archive_name", [
    ("make_directory", "Tool-1.0.zip"),
    ("smart_copy", "Tool-1.0.AppImage"),
    ("mark_as_executable", "Tool-1.0.AppImage"),
    ("copy_contents", "Tool-1.0.zip"),
    ("extract_archive", "Tool-1.0.zip"),
])
def test_a_failed_install_removes_its_scratch_directory(workspace, monkeypatch, target, archive_name):
    write(os.path.join(workspace["scratch"], "leftover"))
    owner = release.archive if target == "extract_archive" else release.fileops
    monkeypatch.setattr(owner, target, failing)

    assert setup_archive(workspace, archive_name = archive_name) is False
    assert not os.path.exists(workspace["scratch"])


def test_an_unknown_release_type_removes_its_scratch_directory(workspace):
    setup_archive(workspace, archive_name = "Tool-1.0.bin")

    assert not os.path.exists(workspace["scratch"])


def test_a_scratch_directory_that_will_not_go_away_does_not_fail_the_install(workspace, monkeypatch):
    removals = []
    monkeypatch.setattr(
        release.fileops, "remove_directory",
        lambda src, **kwargs: removals.append(kwargs) or False)

    assert setup_archive(workspace) is True
    assert removals[0]["exit_on_failure"] is False


def test_a_cleanup_failure_never_quits_the_program(workspace, monkeypatch):
    removals = []
    monkeypatch.setattr(
        release.fileops, "remove_directory",
        lambda src, **kwargs: removals.append(kwargs) or True)

    setup_archive(workspace, exit_on_failure = True)

    assert removals[0]["exit_on_failure"] is False


###########################################################
# Renames
###########################################################

def test_a_file_matched_by_two_renames_is_moved_once(workspace):
    workspace["payload"]["files"] = ["tool-1.0.sh"]

    assert setup_archive(
        workspace,
        rename_files = [
            {"from": "tool-1.0.sh", "to": "tool.sh", "ratio": 90},
            {"from": "tool-1.0.sh", "to": "other.sh", "ratio": 90}]) is True
    assert tree(workspace["install_dir"]) == ["tool.sh"]


###########################################################
# Pretend runs
###########################################################

def test_a_pretend_install_reports_success_without_installing(workspace):
    assert setup_archive(workspace, pretend_run = True) is True
    assert not os.path.exists(workspace["install_dir"])


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_extractor(workspace, monkeypatch, flag):
    seen = []
    monkeypatch.setattr(
        release.archive, "extract_archive",
        lambda **kwargs: seen.append(kwargs) or True)
    setup_archive(workspace, **{flag: True})

    assert seen[0][flag] is True
