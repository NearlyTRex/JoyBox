# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import psv_rom_tool


###########################################################
# Action dispatch
###########################################################

@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, psv_rom_tool)
    harness.calls = []
    for name in ("strip_psv", "unstrip_psv", "trim_psv", "untrim_psv", "verify_psv"):
        monkeypatch.setattr(psv_rom_tool.playstation, name,
            lambda name = name, **kwargs: harness.calls.append((name, kwargs)))
    (tmp_path / "Game.psv").write_bytes(b"x")
    return harness


@pytest.mark.parametrize("flag, action, function, outputs", [
    ("-s", "Strip", "strip_psv", {"dest_psv_file": "Game_stripped.psv"}),
    ("-u", "Unstrip", "unstrip_psv", {"src_psve_file": "Game.psve", "dest_psv_file": "Game_unstripped.psv"}),
    ("-t", "Trim", "trim_psv", {"dest_psv_file": "Game_trimmed.psv"}),
    ("-n", "Untrim", "untrim_psv", {"dest_psv_file": "Game_untrimmed.psv"}),
])
def test_each_conversion_writes_beside_the_source(tool, tmp_path, flag, action, function, outputs):
    tool.run("-i", str(tmp_path), flag, "-d")

    assert tool.previews == [("PSV ROM tool", ["Path: %s" % tmp_path, "Action: %s" % action, "Delete originals: True"])]
    [(called, kwargs)] = tool.calls
    assert called == function
    assert kwargs["src_psv_file"] == str(tmp_path / "Game.psv")
    assert kwargs["delete_original"] is True
    for key, name in outputs.items():
        assert kwargs[key] == str(tmp_path / name)


def test_verify_only_checks_the_dump(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-e")

    assert tool.previews == [("PSV ROM tool", ["Path: %s" % tmp_path, "Action: Verify"])]
    assert tool.calls == [("verify_psv", {"psv_file": str(tmp_path / "Game.psv"),
        "verbose": False, "pretend_run": False, "exit_on_failure": False})]


def test_without_an_action_nothing_is_called(tool, tmp_path):
    tool.run("-i", str(tmp_path), "--no-preview")

    assert tool.calls == []


def test_a_declined_preview_converts_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-s")

    assert tool.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, psv_rom_tool)
