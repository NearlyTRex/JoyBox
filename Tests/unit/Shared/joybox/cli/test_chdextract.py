# Imports
import pytest

# Local imports
from cli_helpers import CommandHarness, Recorder, assert_entry_points
from joybox.cli import chdextract


###########################################################
# chdextract
#
# Each .chd is extracted beside itself, unless either output already exists.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    command = CommandHarness(monkeypatch, chdextract)
    command.extract = Recorder(result = True)
    monkeypatch.setattr(chdextract.chd, "extract_disc_chd", command.extract)
    return command


@pytest.fixture
def discs(tmp_path):
    for name in ["new.chd", "has_bin.chd", "has_bin.bin", "has_toc.chd", "has_toc.cue"]:
        (tmp_path / name).write_bytes(b"")
    return tmp_path


def test_only_chds_without_outputs_are_extracted(tool, discs):
    tool.main("-i", str(discs), "--no-preview")

    assert [call["chd_file"] for call in tool.extract.calls] == [str(discs / "new.chd")]
    call = tool.extract.calls[0]
    assert (call["binary_file"], call["toc_file"]) == (str(discs / "new.bin"), str(discs / "new.cue"))
    assert call["delete_original"] is False


def test_custom_extensions_name_the_outputs(tool, discs):
    tool.main("-i", str(discs), "--no-preview", "-t", ".gdi", "-b", ".raw", "-d")

    outputs = [(call["binary_file"], call["toc_file"]) for call in tool.extract.calls]
    assert (str(discs / "has_bin.raw"), str(discs / "has_bin.gdi")) in outputs
    assert all(call["delete_original"] for call in tool.extract.calls)


def test_the_preview_shows_the_output_extensions(tool, discs):
    tool.main("-i", str(discs))

    assert tool.previews == [("Extract CHD", ["Path: %s" % discs, "Output: .cue + .bin", "Delete originals: False"])]


def test_a_declined_preview_extracts_nothing(tool, discs):
    tool.confirm = False

    tool.main("-i", str(discs))

    assert tool.extract.calls == []


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, chdextract)
