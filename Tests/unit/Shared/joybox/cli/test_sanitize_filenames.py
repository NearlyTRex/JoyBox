# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import sanitize_filenames


###########################################################
# sanitize_filenames
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, sanitize_filenames)
    command.sanitize = Recorder()
    monkeypatch.setattr(sanitize_filenames.fileops, "sanitize_filenames", command.sanitize)
    return command


def test_the_input_directory_is_sanitized(tool, tmp_path):
    tool.main("-i", str(tmp_path), "--no-preview", "-p")

    assert tool.sanitize.calls == [{"path": str(tmp_path), "verbose": False, "pretend_run": True, "exit_on_failure": False}]


def test_the_preview_names_the_path(tool, tmp_path):
    tool.main("-i", str(tmp_path))

    assert tool.previews == [("Sanitize filenames", ["Path: %s" % tmp_path])]
    assert len(tool.sanitize.calls) == 1


def test_a_declined_preview_renames_nothing(tool, tmp_path):
    tool.confirm = False

    tool.main("-i", str(tmp_path))

    assert tool.sanitize.calls == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_missing_input_path_stops_the_run(tool, tmp_path):
    with pytest.raises(SystemExit):
        tool.main("-i", str(tmp_path / "missing"), "--no-preview")
    assert tool.sanitize.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, sanitize_filenames)
