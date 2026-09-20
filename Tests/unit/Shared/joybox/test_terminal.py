# Imports
import builtins
import io
import sys
import pytest

# Local imports
from joybox import terminal


###########################################################
# Terminal output
#
# Colour belongs on a terminal and nowhere else. Escape codes written into a
# redirected file end up in transcripts, logs and pasted output.
###########################################################

class FakeStream(io.StringIO):

    def __init__(self, tty = True):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


@pytest.fixture
def no_color_unset(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising = False)


###########################################################
# Colour support
###########################################################

def test_a_terminal_supports_colour(no_color_unset):
    assert terminal.supports_colour(FakeStream(tty = True)) is True


def test_a_redirected_stream_does_not(no_color_unset):
    assert terminal.supports_colour(FakeStream(tty = False)) is False


def test_no_color_turns_colour_off(monkeypatch):
    # The NO_COLOR convention, honoured even on a real terminal.
    monkeypatch.setenv("NO_COLOR", "1")

    assert terminal.supports_colour(FakeStream(tty = True)) is False


def test_an_empty_no_color_is_not_a_request(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "")

    assert terminal.supports_colour(FakeStream(tty = True)) is True


def test_a_stream_without_isatty_does_not_support_colour(no_color_unset):
    class Bare:
        pass

    assert terminal.supports_colour(Bare()) is False


def test_stdout_is_the_default_stream(monkeypatch, no_color_unset):
    monkeypatch.setattr(sys, "stdout", FakeStream(tty = True))

    assert terminal.supports_colour() is True


###########################################################
# Painting
###########################################################

def test_text_is_wrapped_on_a_terminal(no_color_unset):
    painted = terminal.paint("hello", terminal.RED, FakeStream(tty = True))

    assert painted.startswith(terminal.RED)
    assert painted.endswith(terminal.RESET)
    assert "hello" in painted


def test_text_is_untouched_off_a_terminal(no_color_unset):
    assert terminal.paint("hello", terminal.RED, FakeStream(tty = False)) == "hello"


def test_no_escape_codes_reach_a_redirected_stream(no_color_unset):
    # This is the whole point: a redirected run has to stay pasteable.
    painted = terminal.paint("hello", terminal.RED, FakeStream(tty = False))

    assert "\033" not in painted


def test_every_colour_is_a_distinct_code():
    codes = [terminal.DIM, terminal.BOLD, terminal.RED, terminal.GREEN,
             terminal.YELLOW, terminal.BLUE, terminal.CYAN]

    assert len(set(codes)) == len(codes)


@pytest.mark.parametrize("code", ["DIM", "BOLD", "RED", "GREEN", "YELLOW", "BLUE", "CYAN"])
def test_every_colour_is_an_escape_sequence(code):
    assert getattr(terminal, code).startswith("\033[")


def test_the_reset_code_is_not_a_colour():
    codes = [terminal.DIM, terminal.BOLD, terminal.RED, terminal.GREEN,
             terminal.YELLOW, terminal.BLUE, terminal.CYAN]

    assert terminal.RESET not in codes


def test_empty_text_is_still_wrapped(no_color_unset):
    painted = terminal.paint("", terminal.RED, FakeStream(tty = True))

    assert painted == terminal.RED + terminal.RESET


def test_painting_twice_nests(no_color_unset):
    stream = FakeStream(tty = True)
    once = terminal.paint("hello", terminal.RED, stream)

    assert terminal.paint(once, terminal.BOLD, stream).count("hello") == 1


###########################################################
# Writing
###########################################################

def test_write_reaches_stdout(monkeypatch):
    stream = FakeStream(tty = True)
    monkeypatch.setattr(sys, "stdout", stream)
    terminal.write("streamed")

    assert stream.getvalue() == "streamed"


def test_write_adds_no_newline(monkeypatch):
    # Streamed model output arrives mid-line.
    stream = FakeStream(tty = True)
    monkeypatch.setattr(sys, "stdout", stream)
    terminal.write("chunk")

    assert "\n" not in stream.getvalue()


def test_write_flushes(monkeypatch):
    flushed = []

    class Tracking(FakeStream):
        def flush(self):
            flushed.append(True)

    monkeypatch.setattr(sys, "stdout", Tracking())
    terminal.write("chunk")

    assert flushed


def test_consecutive_writes_concatenate(monkeypatch):
    stream = FakeStream(tty = True)
    monkeypatch.setattr(sys, "stdout", stream)
    terminal.write("one")
    terminal.write("two")

    assert stream.getvalue() == "onetwo"


###########################################################
# Status lines
###########################################################

def test_a_status_line_carries_its_message(capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising = False)
    terminal.status("working")

    assert "working" in capsys.readouterr().out


def test_a_notice_carries_its_message(capsys, monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising = False)
    terminal.notice("careful")

    assert "careful" in capsys.readouterr().out


@pytest.mark.parametrize("call", [terminal.status, terminal.notice])
def test_output_is_indented(capsys, monkeypatch, call):
    monkeypatch.setenv("NO_COLOR", "1")
    call("message")

    assert capsys.readouterr().out.startswith("  ")


@pytest.mark.parametrize("call", [terminal.status, terminal.notice])
def test_captured_output_carries_no_escape_codes(capsys, monkeypatch, call):
    # capsys replaces stdout with a non-tty, which is the redirected case.
    monkeypatch.delenv("NO_COLOR", raising = False)
    call("message")

    assert "\033" not in capsys.readouterr().out


###########################################################
# Reading input
###########################################################

def test_a_line_is_returned(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda prompt = "": "typed")

    assert terminal.read_line("> ") == "typed"


def test_the_prompt_is_shown(monkeypatch):
    seen = []
    monkeypatch.setattr(builtins, "input", lambda prompt = "": seen.append(prompt) or "")
    terminal.read_line("ask> ")

    assert "ask> " in seen[0]


def test_an_empty_line_is_returned_as_empty(monkeypatch):
    # Distinct from None, which means the session is over.
    monkeypatch.setattr(builtins, "input", lambda prompt = "": "")

    assert terminal.read_line("> ") == ""


def test_end_of_input_reads_as_nothing(monkeypatch, capsys):
    def raise_eof(prompt = ""):
        raise EOFError

    monkeypatch.setattr(builtins, "input", raise_eof)

    assert terminal.read_line("> ") is None


def test_an_interrupt_reads_as_nothing(monkeypatch, capsys):
    # Ctrl-C and Ctrl-D both mean "done", not "crash".
    def raise_interrupt(prompt = ""):
        raise KeyboardInterrupt

    monkeypatch.setattr(builtins, "input", raise_interrupt)

    assert terminal.read_line("> ") is None


@pytest.mark.parametrize("error", [EOFError, KeyboardInterrupt])
def test_leaving_ends_the_line(monkeypatch, capsys, error):
    def raise_error(prompt = ""):
        raise error

    monkeypatch.setattr(builtins, "input", raise_error)
    terminal.read_line("> ")

    assert capsys.readouterr().out == "\n"


def test_another_error_is_not_swallowed(monkeypatch):
    def raise_error(prompt = ""):
        raise ValueError("something else")

    monkeypatch.setattr(builtins, "input", raise_error)

    with pytest.raises(ValueError):
        terminal.read_line("> ")
