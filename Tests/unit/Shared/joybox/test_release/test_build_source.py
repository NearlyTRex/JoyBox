# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import GIT_URL, PATCH_BODY, TARBALL_URL, build_source, failing


###########################################################
# Building from source
#
# Fetches a source tree into a scratch directory and runs the build command
# there. The scratch directory is handed to the caller on success and removed
# on every failure.
###########################################################

def source_dir(builder, name = "tool"):
    return os.path.join(builder["scratch"], "Source", name)


###########################################################
# Git sources
###########################################################

def test_a_git_source_is_checked_out_under_its_repo_name(builder):
    info = build_source()

    assert builder["git"][0]["url"] == GIT_URL
    assert builder["git"][0]["output_dir"] == source_dir(builder)
    assert info == {
        "tmp_dir": builder["scratch"],
        "source_dir": source_dir(builder),
        "build_dir": source_dir(builder),
    }


def test_a_git_checkout_starts_clean(builder):
    build_source()

    assert builder["git"][0]["clean"] is True


def test_a_git_branch_is_checked_out_when_named(builder):
    build_source(release_branch = "stable")

    assert builder["git"][0]["branch"] == "stable"


def test_no_branch_checks_out_the_default(builder):
    build_source()

    assert builder["git"][0]["branch"] is None


def test_a_git_url_with_a_trailing_slash_is_still_checked_out(builder):
    info = build_source(release_url = "https://github.com/acme/tool.git/")

    assert builder["downloads"] == []
    assert info["source_dir"] == source_dir(builder)


def test_a_failed_checkout_builds_nothing(builder):
    builder["git_ok"] = False

    assert build_source() is None
    assert builder["commands"] == []


###########################################################
# Archive sources
###########################################################

def test_a_source_archive_is_downloaded_and_unpacked(builder):
    info = build_source(release_url = TARBALL_URL)
    archive_file = os.path.join(builder["scratch"], "Download", "tool-1.0.tar.gz")

    assert builder["downloads"][0]["output_file"] == archive_file
    assert builder["extracts"][0] == (archive_file, source_dir(builder, "tool-1.0"))
    assert info["source_dir"] == source_dir(builder, "tool-1.0")


def test_a_failed_source_download_builds_nothing(builder):
    builder["download_ok"] = False

    assert build_source(release_url = TARBALL_URL) is None
    assert builder["extracts"] == []


def test_a_source_archive_that_will_not_unpack_builds_nothing(builder):
    builder["extract_ok"] = False

    assert build_source(release_url = TARBALL_URL) is None
    assert builder["commands"] == []


def test_no_source_builds_nothing(builder):
    assert build_source(release_url = "") is None
    assert builder["downloads"] == []
    assert builder["git"] == []


###########################################################
# Webpage sources
###########################################################

def test_a_webpage_source_uses_the_newest_matching_link(builder, webpage_url):
    webpage_url["url"] = TARBALL_URL
    info = build_source(
        release_url = "",
        webpage_url = "https://acme.example/downloads",
        webpage_base_url = "https://acme.example",
        starts_with = "tool-",
        ends_with = ".tar.gz")
    asked = webpage_url["asked"][0]

    assert asked["get_latest"] is True
    assert asked["base_url"] == "https://acme.example"
    assert (asked["starts_with"], asked["ends_with"]) == ("tool-", ".tar.gz")
    assert builder["downloads"][0]["url"] == TARBALL_URL
    assert info["source_dir"] == source_dir(builder, "tool-1.0")


def test_a_webpage_without_a_matching_link_builds_nothing(builder, webpage_url, monkeypatch):
    created = []
    monkeypatch.setattr(
        release.fileops, "create_temporary_directory",
        lambda **kwargs: created.append(kwargs) or (True, builder["scratch"]))

    assert build_source(webpage_url = "https://acme.example/downloads") is None
    assert created == []


@pytest.mark.parametrize("value", ["", None])
def test_no_webpage_means_the_release_url_is_used(builder, webpage_url, value):
    build_source(webpage_url = value)

    assert webpage_url["asked"] == []
    assert builder["git"][0]["url"] == GIT_URL


###########################################################
# Building
###########################################################

def test_the_build_command_runs_in_a_shell_in_the_source_tree(builder):
    build_source(build_cmd = ["make", "-j", "4"])
    command = builder["commands"][-1]

    assert command["cmd"] == ["make", "-j", "4"]
    assert command["cwd"] == source_dir(builder)
    assert command["shell"] is True


def test_a_build_directory_is_created_inside_the_source_tree(builder):
    info = build_source(build_dir = "Build")
    build_dir = os.path.join(source_dir(builder), "Build")

    assert info["build_dir"] == build_dir
    assert os.path.isdir(build_dir)
    assert builder["commands"][-1]["cwd"] == build_dir


@pytest.mark.parametrize("value", ["", None])
def test_no_build_directory_builds_in_the_source_tree(builder, value):
    assert build_source(build_dir = value)["build_dir"] == source_dir(builder)


def test_a_failed_build_returns_nothing(builder):
    builder["codes"]["make"] = 2

    assert build_source() is None


def test_patches_are_applied_before_the_build(builder):
    build_source(source_patches = [{"file": "fix.patch", "content": PATCH_BODY}])

    assert [command["cmd"][0] for command in builder["commands"]] == ["Git", "make"]
    assert builder["commands"][0]["cwd"] == source_dir(builder)


def test_a_failed_patch_stops_the_build(builder):
    builder["codes"]["Git"] = 1

    assert build_source(source_patches = [{"file": "fix.patch", "content": PATCH_BODY}]) is None
    assert [command["cmd"][0] for command in builder["commands"]] == ["Git"]


###########################################################
# The scratch directory
###########################################################

def test_a_successful_build_keeps_its_scratch_directory(builder):
    build_source()

    assert os.path.isdir(builder["scratch"])


@pytest.mark.parametrize("break_build", [
    lambda builder, monkeypatch: builder.update(git_ok = False),
    lambda builder, monkeypatch: builder["codes"].update(make = 1),
    lambda builder, monkeypatch: builder["codes"].update(Git = 1),
    lambda builder, monkeypatch: monkeypatch.setattr(release.fileops, "make_directory", failing),
])
def test_a_failed_build_removes_its_scratch_directory(builder, monkeypatch, break_build):
    break_build(builder, monkeypatch)

    assert build_source(source_patches = [{"file": "fix.patch", "content": PATCH_BODY}]) is None
    assert not os.path.exists(builder["scratch"])


@pytest.mark.parametrize("break_build", [
    lambda builder: builder.update(download_ok = False),
    lambda builder: builder.update(extract_ok = False),
])
def test_a_failed_archive_source_removes_its_scratch_directory(builder, break_build):
    break_build(builder)

    assert build_source(release_url = TARBALL_URL) is None
    assert not os.path.exists(builder["scratch"])


def test_a_build_folder_that_cannot_be_made_stops_the_build(builder, monkeypatch):
    real = release.fileops.make_directory

    def make_directory(src, **kwargs):
        if src.endswith("Build"):
            return False
        return real(src = src, **kwargs)

    monkeypatch.setattr(release.fileops, "make_directory", make_directory)

    assert build_source(build_dir = "Build") is None
    assert builder["commands"] == []


def test_no_scratch_directory_builds_nothing(builder, monkeypatch):
    monkeypatch.setattr(
        release.fileops, "create_temporary_directory", lambda **kwargs: (False, ""))

    assert build_source() is None
    assert builder["git"] == []


###########################################################
# Run flags
###########################################################

@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_checkout_and_the_build(builder, flag):
    build_source(**{flag: True})

    assert builder["git"][0][flag] is True
    assert builder["commands"][-1]["kwargs"][flag] is True


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_the_download_and_the_unpack(builder, monkeypatch, flag):
    seen = []
    monkeypatch.setattr(
        release.archive, "extract_archive",
        lambda **kwargs: seen.append(kwargs) or True)
    build_source(release_url = TARBALL_URL, **{flag: True})

    assert builder["downloads"][0][flag] is True
    assert seen[0][flag] is True
