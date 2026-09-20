# Imports
import pytest

# Local imports
from joybox import debug


###########################################################
# Debug helpers
#
# Used to label log lines with where they came from. A frame counted wrongly
# points at this module instead of the caller, which makes every log line
# useless in the same way.
###########################################################

# depth counts frames to skip beyond the immediate caller, so zero names the
# code that called get_source_info and one names its caller. The default of one
# suits a logging helper, which wants the line that called the logger rather
# than the logger itself.

def test_source_info_names_the_callers_file():
    assert "test_debug.py" in debug.get_source_info(depth = 0)


def test_source_info_carries_a_line_number():
    info = debug.get_source_info(depth = 0)

    assert info.startswith("(") and info.endswith(")")
    assert info.split(":")[-1].rstrip(")").isdigit()


def test_source_info_does_not_name_its_own_module():
    # Reporting debug.py for every call is the failure this is guarding.
    reported = debug.get_source_info(depth = 0).strip("()").rsplit(":", 1)[0]

    assert reported == "test_debug.py"


def test_source_info_moves_with_the_call_site():
    first = debug.get_source_info(depth = 0)
    second = debug.get_source_info(depth = 0)

    assert first != second


def test_the_default_depth_names_the_callers_caller():
    # A logging helper wants the line that called it, not its own.
    def helper():
        return debug.get_source_info()

    assert "test_debug.py" in helper()


def test_a_deeper_depth_climbs_further():
    def innermost():
        return debug.get_source_info(depth = 0), debug.get_source_info(depth = 1)

    def outer():
        return innermost()

    immediate, one_up = outer()
    assert immediate != one_up


def test_an_impossible_depth_is_reported_as_unknown():
    # Walking past the top of the stack must not raise.
    assert debug.get_source_info(depth = 10000) == "(unknown:0)"


@pytest.mark.parametrize("depth", [0, 1, 2, 3])
def test_any_reachable_depth_yields_a_location(depth):
    def one():
        return two()

    def two():
        return three()

    def three():
        return debug.get_source_info(depth = depth)

    info = one()
    assert info.startswith("(")
    assert ":" in info


###########################################################
# Backtraces
###########################################################

def test_a_backtrace_names_this_test():
    assert "test_a_backtrace_names_this_test" in debug.get_backtrace()


def test_a_backtrace_lists_several_frames():
    def inner():
        return debug.get_backtrace()

    assert inner().count("File:") > 1


def test_a_backtrace_starts_with_a_newline():
    # It is appended to a log line, so it has to break away from it.
    assert debug.get_backtrace().startswith("\n")


def test_each_backtrace_line_names_a_function():
    for line in debug.get_backtrace().strip().splitlines():
        assert "Function:" in line
        assert "Line:" in line


def test_skipping_drops_the_nearest_frames():
    def inner():
        return debug.get_backtrace(skip = 1)

    assert "inner" not in inner()


def test_not_skipping_keeps_the_nearest_frame():
    def inner():
        return debug.get_backtrace()

    assert "inner" in inner()


def test_a_large_skip_yields_no_frames():
    assert debug.get_backtrace(skip = 10000).strip() == ""
