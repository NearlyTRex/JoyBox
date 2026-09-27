# Imports
import pytest

# Local imports
from joybox.bootstrap import picker


###########################################################
# Parsing a selection
###########################################################

NAMES = ["config", "aptget", "python", "chrome", "steam", "wine"]


@pytest.mark.parametrize("text", ["", "   ", "all", "ALL"])
def test_blank_or_all_selects_everything(text):
    assert picker.parse_selection(text, NAMES) == NAMES


@pytest.mark.parametrize("text, expected", [
    ("2", ["aptget"]),
    ("2 4", ["aptget", "chrome"]),
    ("2,4", ["aptget", "chrome"]),
    ("3-5", ["python", "chrome", "steam"]),
    ("steam chrome", ["chrome", "steam"]),
    ("1 steam 3-3", ["config", "python", "steam"]),
])
def test_numbers_ranges_and_names_select_components(text, expected):
    assert picker.parse_selection(text, NAMES) == expected


def test_the_result_keeps_install_order_whatever_the_typed_order():
    # Components depend on declaration order (python needs aptget first).
    assert picker.parse_selection("python aptget", NAMES) == ["aptget", "python"]


def test_repeats_are_selected_once():
    assert picker.parse_selection("2 2 aptget", NAMES) == ["aptget"]


@pytest.mark.parametrize("text, expected", [
    ("-steam", ["config", "aptget", "python", "chrome", "wine"]),
    ("-5 -6", ["config", "aptget", "python", "chrome"]),
    ("-4-6", ["config", "aptget", "python"]),
    ("all -wine", ["config", "aptget", "python", "chrome", "steam"]),
    ("1-4 -3", ["config", "aptget", "chrome"]),
])
def test_a_leading_dash_leaves_components_out(text, expected):
    assert picker.parse_selection(text, NAMES) == expected


@pytest.mark.parametrize("text", ["0", "7", "nope", "5-2", "-", "2-x"])
def test_bad_entries_are_rejected(text):
    with pytest.raises(ValueError):
        picker.parse_selection(text, NAMES)


def test_a_hyphenated_name_is_a_name_not_a_range():
    names = ["a", "b", "vs-code"]
    assert picker.parse_selection("vs-code", names) == ["vs-code"]


###########################################################
# Prompting
###########################################################

def run_prompt(answers, names = NAMES):
    replies = iter(answers)
    output = []
    chosen = picker.choose_components(names, read = lambda prompt: next(replies), write = output.append)
    return chosen, output


def test_enter_twice_takes_everything():
    chosen, output = run_prompt(["", ""])
    assert chosen == NAMES


def test_a_confirmed_selection_is_returned():
    chosen, output = run_prompt(["4 5", "y"])
    assert chosen == ["chrome", "steam"]


def test_the_menu_numbers_every_component():
    chosen, output = run_prompt(["", ""])
    for number, name in enumerate(NAMES, 1):
        assert f"  {number}) {name}" in output


def test_an_invalid_selection_asks_again():
    chosen, output = run_prompt(["99", "2", ""])
    assert chosen == ["aptget"]
    assert any("out of range" in line for line in output)


def test_excluding_everything_asks_again():
    chosen, output = run_prompt(["all -1-6", "1", ""])
    assert chosen == ["config"]
    assert "Nothing selected." in output


def test_declining_the_confirmation_asks_again():
    chosen, output = run_prompt(["1", "n", "2", "y"])
    assert chosen == ["aptget"]


def test_an_unclear_confirmation_asks_again_rather_than_declining():
    chosen, output = run_prompt(["1", "steam", "y"])
    assert chosen == ["config"]


@pytest.mark.parametrize("answers", [["q"], ["QUIT"], ["1", "q"]])
def test_quitting_returns_none(answers):
    chosen, output = run_prompt(answers)
    assert chosen is None
