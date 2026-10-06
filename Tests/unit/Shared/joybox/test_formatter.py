# Imports
import os

# Third-party imports
import pytest

# Local imports
from fakes import RecordingCommand
from joybox import formatter


###########################################################
# clang-format invocation
#
# The style choices are exclusive: a named style wins over an inline one,
# which wins over a style file.
###########################################################

def test_a_plain_format_edits_the_file_in_place(monkeypatch):
    recorder = RecordingCommand(monkeypatch)

    assert formatter.format_cpp_file("main.cpp") is True
    assert recorder.only() == ["clang-format", "-i", "main.cpp"]


def test_a_named_style_wins_over_the_others(monkeypatch):
    recorder = RecordingCommand(monkeypatch)
    formatter.format_cpp_file("main.cpp", style_name = "llvm", style_inline = "{IndentWidth: 2}", style_file = "x")

    assert recorder.only() == ["clang-format", "-style", "llvm", "-i", "main.cpp"]


def test_an_inline_style_is_one_unquoted_argument(monkeypatch):
    # No shell runs the command, so literal quotes would reach clang-format.
    recorder = RecordingCommand(monkeypatch)
    formatter.format_cpp_file("main.cpp", style_inline = "{IndentWidth: 2}", style_file = "x")

    assert recorder.only() == ["clang-format", "-style={IndentWidth: 2}", "-i", "main.cpp"]


def test_a_style_file_is_passed_as_an_absolute_path(monkeypatch, tmp_path):
    recorder = RecordingCommand(monkeypatch)
    monkeypatch.chdir(tmp_path)
    formatter.format_cpp_file("main.cpp", style_file = ".clang-format")

    assert recorder.value_after("-style") == os.path.realpath(tmp_path / ".clang-format")


@pytest.mark.parametrize("returncode, expected", [(0, True), (1, False)])
def test_the_result_follows_the_exit_code(monkeypatch, returncode, expected):
    RecordingCommand(monkeypatch, returncode = returncode)

    assert formatter.format_cpp_file("main.cpp") is expected
