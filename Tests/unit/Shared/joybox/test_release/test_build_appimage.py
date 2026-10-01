# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import build_appimage, failing, tree, write


###########################################################
# Building an AppImage
#
# Builds from source, lays the result out as an AppDir, packs it with
# appimagetool and installs the AppImage under the tool's stable name.
###########################################################

def appdir(builder):
    return os.path.join(builder["scratch"], "AppImage")


def test_the_appimage_is_installed_under_the_install_name(builder):
    assert build_appimage(builder) is True
    assert tree(builder["install_dir"]) == ["Tool.AppImage"]


def test_appimagetool_packs_the_appdir_from_the_scratch_directory(builder):
    build_appimage(builder)
    command = builder["commands"][-1]

    assert command["cmd"] == ["AppImageTool", appdir(builder)]
    assert command["cwd"] == builder["scratch"]


def test_built_files_are_laid_out_in_the_appdir(builder, monkeypatch):
    copied = []
    real = release.fileops.smart_copy
    monkeypatch.setattr(
        release.fileops, "smart_copy",
        lambda src, dest, **kwargs: copied.append((src, dest)) or real(src = src, dest = dest, **kwargs))

    assert build_appimage(builder, internal_copies = [
        {"from": os.path.join("Source", "tool", "tool"), "to": os.path.join("AppImage", "usr", "bin", "tool")}]) is True
    assert copied[0] == (
        os.path.join(builder["scratch"], "Source", "tool", "tool"),
        os.path.join(appdir(builder), "usr", "bin", "tool"))


def test_appimagetool_files_come_from_the_tools_directory(builder):
    write(os.path.join(builder["tools_root"], "AppImageTool", "AppRun"), "runner")

    assert build_appimage(builder, internal_copies = [
        {"from": os.path.join("AppImageTool", "AppRun"), "to": os.path.join("AppImage", "AppRun")}]) is True


def test_a_missing_appdir_file_stops_the_build(builder):
    assert build_appimage(builder, internal_copies = [{"from": "absent", "to": "AppImage/absent"}]) is False
    assert [command["cmd"][0] for command in builder["commands"]] == ["make"]


def test_appdir_symlinks_are_made_inside_the_appdir(builder, monkeypatch):
    linked = []
    monkeypatch.setattr(
        release.fileops, "create_symlink",
        lambda src, dest, cwd = None, **kwargs: linked.append((src, dest, cwd)) or True)

    assert build_appimage(builder, internal_symlinks = [{"from": "usr/bin/tool", "to": "AppRun"}]) is True
    assert linked == [("usr/bin/tool", "AppRun", appdir(builder))]


def test_a_failed_symlink_stops_the_build(builder, monkeypatch):
    monkeypatch.setattr(release.fileops, "create_symlink", failing)

    assert build_appimage(builder, internal_symlinks = [{"from": "usr/bin/tool", "to": "AppRun"}]) is False


def test_a_failed_pack_installs_nothing(builder):
    builder["codes"]["AppImageTool"] = 1

    assert build_appimage(builder) is False
    assert tree(builder["install_dir"]) == []


def test_a_pack_that_produced_nothing_installs_nothing(builder):
    builder["outputs"]["AppImageTool"] = {}

    assert build_appimage(builder) is False


def test_a_failed_build_never_packs(builder):
    builder["codes"]["make"] = 1

    assert build_appimage(builder) is False
    assert [command["cmd"][0] for command in builder["commands"]] == ["make"]


def test_a_folder_that_cannot_be_made_stops_the_build(builder, monkeypatch):
    real = release.fileops.make_directory

    def make_directory(src, **kwargs):
        if src == appdir(builder):
            return False
        return real(src = src, **kwargs)

    monkeypatch.setattr(release.fileops, "make_directory", make_directory)

    assert build_appimage(builder) is False


def test_an_appimage_that_will_not_copy_installs_nothing(builder, monkeypatch):
    monkeypatch.setattr(release.fileops, "smart_copy", failing)

    assert build_appimage(builder) is False


###########################################################
# Extra files and backups
###########################################################

def test_extra_files_are_installed_beside_the_appimage(builder):
    builder["outputs"]["make"] = {"tool.dat": "data"}

    assert build_appimage(builder, external_copies = [
        {"from": os.path.join("Source", "tool", "tool.dat"), "to": "tool.dat"}]) is True
    assert tree(builder["install_dir"]) == ["Tool.AppImage", "tool.dat"]


def test_a_missing_extra_file_fails_the_install(builder):
    assert build_appimage(builder, external_copies = [{"from": "absent", "to": "absent"}]) is False


def test_the_appimage_is_backed_up_to_the_requested_locker(builder, backups):
    build_appimage(builder, backups_dir = "/locker/tools", locker_type = "Remote")

    assert backups[0][0] == os.path.join(builder["scratch"], "Tool-x86_64.AppImage")
    assert backups[0][1] == "relative/Tool.AppImage"
    assert backups[0][2]["locker_type"] == "Remote"


def test_the_appimage_backup_can_be_skipped(builder, backups):
    build_appimage(builder, backups_dir = "/locker/tools", skip_autobackup = True)

    assert backups == []


def test_a_failed_appimage_backup_fails_the_build(builder, backups, monkeypatch):
    monkeypatch.setattr(release.locker, "backup", failing)

    assert build_appimage(builder, backups_dir = "/locker/tools") is False


###########################################################
# Cleanup, pretend runs and run flags
###########################################################

@pytest.mark.parametrize("options", [
    {},
    {"output_file": "absent.AppImage"},
    {"internal_copies": [{"from": "absent", "to": "AppImage/absent"}]},
    {"external_copies": [{"from": "absent", "to": "absent"}]},
])
def test_the_appimage_scratch_directory_is_always_removed(builder, options):
    build_appimage(builder, **options)

    assert not os.path.exists(builder["scratch"])


def test_a_pretend_appimage_build_reports_success_without_installing(builder):
    builder["outputs"]["AppImageTool"] = {}

    assert build_appimage(builder, pretend_run = True) is True
    assert not os.path.exists(builder["install_dir"])


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_pack_and_the_backup(builder, backups, flag):
    build_appimage(builder, backups_dir = "/locker/tools", **{flag: True})

    assert builder["commands"][-1]["kwargs"][flag] is True
    assert backups[0][2][flag] is True


def test_appimage_build_options_reach_the_source_build(builder, monkeypatch):
    seen = []
    monkeypatch.setattr(release, "build_from_source", lambda **kwargs: seen.append(kwargs) or None)

    assert build_appimage(builder, release_branch = "stable", build_dir = "Build") is False
    assert seen[0]["release_branch"] == "stable"
    assert seen[0]["build_dir"] == "Build"
