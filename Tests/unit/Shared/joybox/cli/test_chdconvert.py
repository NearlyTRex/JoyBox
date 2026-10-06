# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import chdconvert


###########################################################
# Conversion selection
#
# Only images of the chosen types are converted, and an image whose CHD
# already exists is left alone so a rerun picks up where it stopped.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, chdconvert)
    harness.created = []
    monkeypatch.setattr(chdconvert.chd, "create_disc_chd", lambda **kwargs: harness.created.append(kwargs))
    for name in ("one.iso", "two.cue", "two.bin", "three.gdi", "done.iso", "done.chd"):
        (tmp_path / name).write_bytes(b"")
    return harness


def created_names(tool):
    return sorted(call["chd_file"].rsplit("/", 1)[-1] for call in tool.created)


def test_each_image_without_a_chd_is_converted(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-d")

    assert created_names(tool) == ["one.chd", "three.chd", "two.chd"]
    assert all(call["delete_original"] for call in tool.created)
    assert {call["source_iso"] for call in tool.created} == {
        str(tmp_path / "one.iso"), str(tmp_path / "two.cue"), str(tmp_path / "three.gdi")}


def test_only_the_selected_image_types_are_converted(tool, tmp_path):
    tool.run("--no-preview", "-i", str(tmp_path), "-t", "CUE")

    assert created_names(tool) == ["two.chd"]


def test_the_preview_describes_the_run(tool, tmp_path):
    tool.run("-i", str(tmp_path))

    [(title, details)] = tool.previews
    assert title == "Convert to CHD"
    assert details[0] == "Path: %s" % tmp_path
    assert len(tool.created) == 3


def test_a_cancelled_preview_converts_nothing(tool, tmp_path):
    tool.confirm = False

    tool.run("-i", str(tmp_path))

    assert tool.created == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, chdconvert)
