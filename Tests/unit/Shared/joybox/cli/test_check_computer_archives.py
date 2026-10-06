# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import check_computer_archives


###########################################################
# Executable size limit
#
# 4092 MB is the volume size backup_tool splits at; a larger installer
# would not fit one volume.
###########################################################

LIMIT = 4290772992


@pytest.fixture
def tool(monkeypatch, tmp_path):
    harness = CommandHarness(monkeypatch, check_computer_archives)
    harness.sizes = {}
    real_getsize = os.path.getsize
    monkeypatch.setattr(check_computer_archives.os.path, "getsize",
        lambda path: harness.sizes.get(os.path.basename(path), real_getsize(path)))
    for name in ("setup.exe", "readme.txt"):
        (tmp_path / name).write_bytes(b"x")
    return harness


def test_executables_at_the_limit_pass(tool, tmp_path):
    tool.sizes["setup.exe"] = LIMIT

    tool.run("-i", str(tmp_path))

    assert tool.errors == []
    assert tool.infos == ["Checking exe file %s ..." % (tmp_path / "setup.exe")]


def test_an_executable_over_the_limit_stops_the_run(tool, tmp_path):
    tool.sizes["setup.exe"] = LIMIT + 1

    assert tool.exit_code("-i", str(tmp_path)) != 0
    assert tool.errors == ["Executable '%s' is larger than 4092 MB" % (tmp_path / "setup.exe")]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, check_computer_archives)
