# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import wiiu_rom_tool


###########################################################
# NUS packages
#
# A package is a directory holding title.tik; other tickets are ignored.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, wiiu_rom_tool)
    harness.decrypted = []
    harness.verified = []
    (tmp_path / "Game").mkdir()
    (tmp_path / "Game" / "title.tik").write_bytes(b"")
    (tmp_path / "Other").mkdir()
    (tmp_path / "Other" / "other.tik").write_bytes(b"")
    harness.package = str(tmp_path / "Game")
    nintendo = wiiu_rom_tool.nintendo
    monkeypatch.setattr(nintendo, "decrypt_wiiu_nus_package", lambda **kwargs: harness.decrypted.append(kwargs))
    monkeypatch.setattr(nintendo, "verify_wiiu_nus_package", lambda **kwargs: harness.verified.append(kwargs))
    return harness


def test_decrypt_handles_each_package_directory(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-r", "-d")

    assert tool.decrypted == [{
        "nus_package_dir": tool.package, "delete_original": True,
        "verbose": False, "pretend_run": False, "exit_on_failure": False}]
    assert tool.verified == []


def test_verify_leaves_packages_unchanged(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-e")

    assert [call["nus_package_dir"] for call in tool.verified] == [tool.package]
    assert tool.decrypted == []


def test_without_an_action_nothing_is_done(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path))

    assert tool.decrypted == tool.verified == []


@pytest.mark.parametrize("flags, details", [
    (["-r", "-d"], ["Action: Decrypt NUS", "Delete originals: True"]),
    (["-e"], ["Action: Verify NUS"]),
    ([], ["Action: None"]),
])
def test_the_preview_describes_the_action(tool, tmp_path, flags, details):
    tool.run("-i", str(tmp_path), *flags)

    assert tool.previews[0][1][1:] == details


def test_a_cancelled_preview_does_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path), "-r")

    assert tool.decrypted == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, wiiu_rom_tool)
