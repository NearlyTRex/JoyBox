# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import release
from release_helpers import PATCH_BODY, failing


###########################################################
# Source patches
#
# A patch entry either carries its content inline or names a file to read it
# from. An unreadable named file has to stop the build rather than silently
# apply nothing.
###########################################################

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


@pytest.mark.parametrize("field", ["file", "content", "path"])
def test_a_null_field_is_treated_as_absent(field):
    entry = {"file": "fix.patch", "content": PATCH_BODY, "path": ""}
    entry[field] = None
    name, content = release.resolve_patch_entry(entry)

    assert isinstance(name, str)
    assert isinstance(content, str)


###########################################################
# Applying patches
###########################################################

@pytest.fixture
def patching(tmp_path, monkeypatch):
    applied = []
    state = {"code": 0, "applied": applied, "source_dir": str(tmp_path / "source"), "patch_dir": str(tmp_path / "patches")}

    def run_returncode_command(cmd, options = None, **kwargs):
        with open(cmd[2]) as handle:
            applied.append({"cmd": cmd, "cwd": options.get_cwd(), "body": handle.read(), "kwargs": kwargs})
        return state["code"]

    monkeypatch.setattr(release.command, "run_returncode_command", run_returncode_command)
    monkeypatch.setattr(release.programs, "get_tool_program", lambda name: "/usr/bin/" + name.lower())
    return state


def apply(patching, patches, **kwargs):
    return release.apply_source_patches(
        source_patches = patches,
        source_dir = patching["source_dir"],
        patch_dir = patching["patch_dir"],
        **kwargs)


def test_each_patch_is_applied_with_git_in_the_source_tree(patching):
    assert apply(patching, [{"file": "fix.patch", "content": PATCH_BODY}]) is True
    applied = patching["applied"][0]

    assert applied["cmd"][:2] == ["/usr/bin/git", "apply"]
    assert applied["cwd"] == patching["source_dir"]
    assert applied["body"] == PATCH_BODY


def test_patches_are_applied_in_order(patching):
    apply(patching, [
        {"file": "first.patch", "content": "one"},
        {"file": "second.patch", "content": "two"}])

    assert [entry["body"] for entry in patching["applied"]] == ["one", "two"]


def test_a_patch_name_gains_the_patch_extension(patching):
    apply(patching, [{"file": "fix", "content": PATCH_BODY}])

    assert patching["applied"][0]["cmd"][2] == os.path.join(patching["patch_dir"], "fix.patch")


def test_an_unnamed_inline_patch_is_still_applied(patching):
    assert apply(patching, [{"content": PATCH_BODY}]) is True
    assert patching["applied"][0]["body"] == PATCH_BODY


def test_a_patch_with_no_content_stops_the_build(patching, tmp_path):
    entry = {"file": "fix.patch", "path": str(tmp_path / "absent.patch")}

    assert apply(patching, [entry]) is False
    assert patching["applied"] == []


def test_an_unreadable_patch_stops_the_build(patching, tmp_path, monkeypatch):
    patch_path = tmp_path / "fix.patch"
    patch_path.write_text(PATCH_BODY)
    monkeypatch.setattr(release.serialization, "read_text_file", lambda *a, **k: None)

    assert apply(patching, [{"path": str(patch_path)}]) is False


def test_a_patch_that_will_not_apply_stops_the_build(patching):
    patching["code"] = 1

    assert apply(patching, [
        {"file": "a.patch", "content": "one"},
        {"file": "b.patch", "content": "two"}]) is False
    assert len(patching["applied"]) == 1


def test_a_patch_that_cannot_be_written_stops_the_build(patching, monkeypatch):
    monkeypatch.setattr(release.fileops, "touch_file", failing)

    assert apply(patching, [{"file": "fix.patch", "content": PATCH_BODY}]) is False
    assert patching["applied"] == []


@pytest.mark.parametrize("patches", [[], None, "fix.patch"])
def test_no_patch_list_applies_nothing(patching, patches):
    assert apply(patching, patches) is True
    assert patching["applied"] == []


@pytest.mark.parametrize("flag", ["verbose", "pretend_run", "exit_on_failure"])
def test_run_flags_reach_git_apply(patching, monkeypatch, flag):
    seen = []
    monkeypatch.setattr(
        release.command, "run_returncode_command",
        lambda cmd, options = None, **kwargs: seen.append(kwargs) or 0)
    apply(patching, [{"file": "fix.patch", "content": PATCH_BODY}], **{flag: True})

    assert seen[0][flag] is True
