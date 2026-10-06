# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import audio_conversion_tool


###########################################################
# Input dispatch
#
# A file is converted on its own and a directory book by book; the outcome
# of the conversion becomes the exit status.
###########################################################

@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, audio_conversion_tool)
    harness.files = []
    harness.dirs = []
    harness.result = True

    def convert_file(**kwargs):
        harness.files.append(kwargs)
        return harness.result

    def convert_dir(**kwargs):
        harness.dirs.append(kwargs)
        return harness.result

    monkeypatch.setattr(audio_conversion_tool.audible, "decrypt_aax_to_m4a", convert_file)
    monkeypatch.setattr(audio_conversion_tool.audible, "decrypt_aax_directory", convert_dir)
    return harness


def test_a_file_is_converted_to_the_chosen_output(tool, tmp_path):
    book = tmp_path / "book.aax"
    book.write_bytes(b"")

    tool.run("-i", str(book), "-o", "out.m4a", "-k", "1a2b3c4d", "--overwrite")

    assert tool.dirs == []
    [call] = tool.files
    assert call["input_file"] == str(book)
    assert call["output_file"] == "out.m4a"
    assert call["activation_bytes"] == "1a2b3c4d"
    assert call["overwrite"] is True


def test_a_directory_is_converted_book_by_book(tool, tmp_path):
    tool.run("-i", str(tmp_path), "-r", "-f", "authcode")

    assert tool.files == []
    [call] = tool.dirs
    assert call["input_dir"] == str(tmp_path)
    assert call["output_dir"] is None
    assert call["recursive"] is True
    assert call["authcode_file"] == "authcode"


def test_a_failed_conversion_exits_with_an_error(tool, tmp_path):
    tool.result = False

    assert tool.exit_code("-i", str(tmp_path)) != 0


def test_an_input_that_is_neither_file_nor_directory_is_refused(tool, tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)

    assert tool.exit_code("-i", str(fifo)) != 0

    assert tool.errors[0] == f"Input is not a file or directory: {fifo}"
    assert tool.files == tool.dirs == []



def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, audio_conversion_tool)
