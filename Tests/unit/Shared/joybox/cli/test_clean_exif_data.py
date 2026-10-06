# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import clean_exif_data


###########################################################
# Input handling
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, clean_exif_data)
    harness.cleaned = Recorder(result = True)
    monkeypatch.setattr(clean_exif_data.asset, "clean_exif_data", harness.cleaned)
    return harness


def test_the_input_is_handed_to_exiftool(tool, tmp_path):
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(b"x")

    tool.run("-i", str(photo), "-p")

    assert tool.cleaned.calls == [{"asset_file": str(photo), "verbose": False, "pretend_run": True, "exit_on_failure": False}]


def test_a_missing_input_stops_before_cleaning(tool, tmp_path):
    assert tool.exit_code("-i", str(tmp_path / "gone.jpg")) != 0
    assert tool.cleaned.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, clean_exif_data)
