# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import build_binary, failing, tree


###########################################################
# Building a binary
#
# Builds from source, then installs the one file the build produced under
# the tool's stable name. A built archive can instead be unpacked and its
# contents installed.
###########################################################

def test_the_built_file_is_installed_under_the_install_name(builder):
    assert build_binary(builder) is True
    assert tree(builder["install_dir"]) == ["Tool"]


def test_the_install_name_keeps_the_built_extension(builder):
    builder["outputs"]["make"] = {"tool.exe": "binary"}

    assert build_binary(builder, output_file = "tool.exe") is True
    assert tree(builder["install_dir"]) == ["Tool.exe"]


def test_an_output_given_as_an_extension_names_the_install(builder):
    builder["outputs"]["make"] = {"tool-1.0.bin": "binary"}

    assert build_binary(builder, output_file = ".bin") is True
    assert tree(builder["install_dir"]) == ["Tool.bin"]


def test_the_output_directory_narrows_the_search(builder):
    builder["outputs"]["make"] = {"tool": "decoy", os.path.join("out", "tool"): "binary"}

    assert build_binary(builder, output_dir = "out") is True
    with open(os.path.join(builder["install_dir"], "Tool")) as handle:
        assert handle.read() == "binary"


def test_a_build_that_produced_nothing_installs_nothing(builder):
    builder["outputs"]["make"] = {}

    assert build_binary(builder) is False
    assert tree(builder["install_dir"]) == []


def test_a_failed_build_installs_nothing(builder):
    builder["codes"]["make"] = 1

    assert build_binary(builder) is False
    assert not os.path.exists(builder["install_dir"])


###########################################################
# Built archives
###########################################################

def test_a_built_archive_is_unpacked_from_the_searched_directory(builder):
    builder["outputs"]["make"] = {"tool.zip": "archive"}

    assert build_binary(builder, output_file = "tool.zip", search_file = "tool") is True
    assert builder["extracts"][-1][1] == os.path.join(builder["scratch"], "Extract")
    assert tree(builder["install_dir"]) == ["tool"]


def test_a_search_file_that_is_not_there_installs_the_whole_archive(builder):
    builder["outputs"]["make"] = {"tool.zip": "archive"}

    assert build_binary(builder, output_file = "tool.zip", search_file = "absent") is True
    assert tree(builder["install_dir"]) == [
        os.path.join("Tool", "bin", "tool"), os.path.join("Tool", "share", "tool.dat")]


@pytest.mark.parametrize("search_file", ["", None])
def test_a_built_archive_without_a_search_file_is_installed_as_is(builder, search_file):
    builder["outputs"]["make"] = {"tool.zip": "archive"}

    assert build_binary(builder, output_file = "tool.zip", search_file = search_file) is True
    assert tree(builder["install_dir"]) == ["Tool.zip"]


def test_a_built_archive_that_will_not_unpack_installs_nothing(builder):
    builder["outputs"]["make"] = {"tool.zip": "archive"}
    builder["extract_ok"] = False

    assert build_binary(builder, output_file = "tool.zip", search_file = "tool") is False


def test_a_built_archive_that_will_not_copy_installs_nothing(builder, monkeypatch):
    builder["outputs"]["make"] = {"tool.zip": "archive"}
    monkeypatch.setattr(release.fileops, "copy_contents", failing)

    assert build_binary(builder, output_file = "tool.zip", search_file = "tool") is False


###########################################################
# Extra files and backups
###########################################################

def test_extra_files_are_copied_from_the_build(builder):
    builder["outputs"]["make"] = {"tool": "binary", "tool.dat": "data"}

    assert build_binary(builder, external_copies = [
        {"from": os.path.join("Source", "tool", "tool.dat"), "to": os.path.join("share", "tool.dat")}]) is True
    assert tree(builder["install_dir"]) == ["Tool", os.path.join("share", "tool.dat")]


def test_a_missing_extra_file_fails_the_install(builder):
    assert build_binary(builder, external_copies = [{"from": "absent", "to": "absent"}]) is False


def test_the_built_file_is_backed_up_to_the_requested_locker(builder, backups):
    build_binary(builder, backups_dir = "/locker/tools", locker_type = "Remote")

    assert backups[0][0].endswith(os.path.join("Source", "tool", "tool"))
    assert backups[0][1] == "relative/Tool"
    assert backups[0][2]["locker_type"] == "Remote"


@pytest.mark.parametrize("options", [{"skip_autobackup": True}, {"backups_dir": ""}])
def test_the_built_file_backup_can_be_skipped(builder, backups, options):
    build_binary(builder, **dict({"backups_dir": "/locker/tools"}, **options))

    assert backups == []


def test_a_failed_backup_fails_the_build(builder, backups, monkeypatch):
    monkeypatch.setattr(release.locker, "backup", failing)

    assert build_binary(builder, backups_dir = "/locker/tools") is False


###########################################################
# Failures and cleanup
###########################################################

def test_an_install_folder_that_cannot_be_made_installs_nothing(builder, monkeypatch):
    real = release.fileops.make_directory

    def make_directory(src, **kwargs):
        if src == builder["install_dir"]:
            return False
        return real(src = src, **kwargs)

    monkeypatch.setattr(release.fileops, "make_directory", make_directory)

    assert build_binary(builder) is False


def test_a_built_file_that_will_not_copy_installs_nothing(builder, monkeypatch):
    monkeypatch.setattr(release.fileops, "smart_copy", failing)

    assert build_binary(builder) is False


@pytest.mark.parametrize("options", [
    {},
    {"output_file": "absent"},
    {"external_copies": [{"from": "absent", "to": "absent"}]},
])
def test_the_scratch_directory_is_always_removed(builder, options):
    build_binary(builder, **options)

    assert not os.path.exists(builder["scratch"])


def test_a_failed_backup_still_removes_the_scratch_directory(builder, backups, monkeypatch):
    monkeypatch.setattr(release.locker, "backup", failing)
    build_binary(builder, backups_dir = "/locker/tools")

    assert not os.path.exists(builder["scratch"])


###########################################################
# Pretend runs and run flags
###########################################################

def test_a_pretend_build_reports_success_without_installing(builder):
    builder["outputs"]["make"] = {}

    assert build_binary(builder, pretend_run = True) is True
    assert not os.path.exists(builder["install_dir"])


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_build_and_the_backup(builder, backups, flag):
    build_binary(builder, backups_dir = "/locker/tools", **{flag: True})

    assert builder["commands"][-1]["kwargs"][flag] is True
    assert backups[0][2][flag] is True


def test_build_options_reach_the_source_build(builder, monkeypatch):
    seen = []
    monkeypatch.setattr(release, "build_from_source", lambda **kwargs: seen.append(kwargs) or None)
    patches = [{"file": "fix.patch", "content": "x"}]

    assert build_binary(
        builder, release_branch = "stable", build_dir = "Build",
        webpage_url = "https://acme.example", source_patches = patches) is False
    assert seen[0]["release_branch"] == "stable"
    assert seen[0]["build_dir"] == "Build"
    assert seen[0]["webpage_url"] == "https://acme.example"
    assert seen[0]["source_patches"] == patches
