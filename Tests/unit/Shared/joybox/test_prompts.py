# Imports
import builtins
import pytest

# Local imports
from joybox import prompts


###########################################################
# Interactive prompts
#
# prompt_for_preview is the confirmation gate in front of every destructive
# script, so a default that answers yes on its own would run the operation
# without being asked for.
###########################################################

@pytest.fixture
def answers(monkeypatch):
    queued = []
    seen = []

    def fake_input(prompt = ""):
        seen.append(prompt)
        if not queued:
            raise AssertionError("prompt asked for more input than was queued")
        return queued.pop(0)

    monkeypatch.setattr(builtins, "input", fake_input)
    return type("Answers", (), {"queue": queued, "prompts": seen})()


###########################################################
# Values
###########################################################

def test_an_entered_value_is_returned(answers):
    answers.queue.append("Chrono Trigger")

    assert prompts.prompt_for_value("Game") == "Chrono Trigger"


def test_an_empty_entry_takes_the_default(answers):
    answers.queue.append("")

    assert prompts.prompt_for_value("Game", "Doom") == "Doom"


def test_an_empty_entry_without_a_default_is_nothing(answers):
    answers.queue.append("")

    assert prompts.prompt_for_value("Game") is None


def test_a_default_is_shown_in_the_prompt(answers):
    answers.queue.append("")
    prompts.prompt_for_value("Game", "Doom")

    assert "Doom" in answers.prompts[0]


def test_whitespace_is_kept_in_a_plain_value(answers):
    # Paths can legitimately end in a space on some filesystems.
    answers.queue.append(" Chrono Trigger ")

    assert prompts.prompt_for_value("Game") == " Chrono Trigger "


###########################################################
# Integers
###########################################################

def test_an_integer_is_parsed(answers):
    answers.queue.append("42")

    assert prompts.prompt_for_int("Count") == 42


def test_a_negative_integer_is_parsed(answers):
    answers.queue.append("-1")

    assert prompts.prompt_for_int("Count") == -1


def test_a_non_integer_is_re_prompted(answers):
    answers.queue.extend(["abc", "7"])

    assert prompts.prompt_for_int("Count") == 7
    assert len(answers.prompts) == 2


def test_an_integer_default_is_used(answers):
    answers.queue.append("")

    assert prompts.prompt_for_int("Count", 5) == 5


def test_the_older_integer_alias_is_the_same_function():
    assert prompts.prompt_for_integer_value is prompts.prompt_for_int


###########################################################
# Choices
###########################################################

def test_a_valid_choice_is_returned(answers):
    answers.queue.append("yes")

    assert prompts.prompt_for_choice("Continue", ["yes", "no"]) == "yes"


def test_a_choice_is_returned_in_its_canonical_form(answers):
    # The caller compares the result against its own choice list.
    answers.queue.append("  YES  ")

    assert prompts.prompt_for_choice("Continue", ["yes", "no"]) == "yes"


def test_an_invalid_choice_is_re_prompted(answers):
    answers.queue.extend(["maybe", "no"])

    assert prompts.prompt_for_choice("Continue", ["yes", "no"]) == "no"


def test_a_choice_default_is_accepted(answers):
    answers.queue.append("")

    assert prompts.prompt_for_choice("Continue", ["yes", "no"], "yes") == "yes"


###########################################################
# Files
###########################################################

def test_an_existing_file_is_accepted(answers, tmp_path):
    target = tmp_path / "game.json"
    target.write_text("{}")
    answers.queue.append(str(target))

    assert prompts.prompt_for_file("File") == str(target)


def test_a_missing_file_is_re_prompted(answers, tmp_path):
    target = tmp_path / "game.json"
    target.write_text("{}")
    answers.queue.extend([str(tmp_path / "absent.json"), str(target)])

    assert prompts.prompt_for_file("File") == str(target)
    assert len(answers.prompts) == 2


def test_an_existing_directory_is_accepted(answers, tmp_path):
    answers.queue.append(str(tmp_path))

    assert prompts.prompt_for_file("Path") == str(tmp_path)


###########################################################
# Confirmation
###########################################################

@pytest.mark.parametrize("entry", ["y", "Y", "yes", "YES", " yes "])
def test_an_affirmative_answer_confirms(answers, entry):
    answers.queue.append(entry)

    assert prompts.prompt_for_confirmation("Proceed?") is True


@pytest.mark.parametrize("entry", ["n", "N", "no", "NO", " no "])
def test_a_negative_answer_declines(answers, entry):
    answers.queue.append(entry)

    assert prompts.prompt_for_confirmation("Proceed?") is False


def test_an_empty_answer_takes_the_default(answers):
    answers.queue.append("")

    assert prompts.prompt_for_confirmation("Proceed?") is False


def test_an_empty_answer_takes_an_affirmative_default(answers):
    answers.queue.append("")

    assert prompts.prompt_for_confirmation("Proceed?", default_yes = True) is True


def test_declining_is_the_default(answers):
    # A stray newline must not start a destructive operation.
    answers.queue.append("")

    assert prompts.prompt_for_confirmation("Delete everything?") is False


def test_an_unrecognised_answer_is_re_prompted(answers):
    answers.queue.extend(["maybe", "y"])

    assert prompts.prompt_for_confirmation("Proceed?") is True
    assert len(answers.prompts) == 2


def test_the_default_is_shown_in_the_suffix(answers):
    answers.queue.append("")
    prompts.prompt_for_confirmation("Proceed?", default_yes = True)

    assert "[Y/n]" in answers.prompts[0]


def test_a_negative_default_is_shown_in_the_suffix(answers):
    answers.queue.append("")
    prompts.prompt_for_confirmation("Proceed?")

    assert "[y/N]" in answers.prompts[0]


###########################################################
# Preview
###########################################################

def test_a_preview_confirms_on_yes(answers):
    answers.queue.append("y")

    assert prompts.prompt_for_preview("Upload", ["/a", "/b"]) is True


def test_a_preview_declines_on_no(answers):
    answers.queue.append("n")

    assert prompts.prompt_for_preview("Upload", ["/a", "/b"]) is False


def test_a_preview_defaults_to_yes(answers):
    answers.queue.append("")

    assert prompts.prompt_for_preview("Upload", ["/a"]) is True


def test_a_preview_can_default_to_no(answers):
    answers.queue.append("")

    assert prompts.prompt_for_preview("Upload", ["/a"], default_yes = False) is False


def test_a_preview_with_no_details_still_asks(answers):
    answers.queue.append("n")

    assert prompts.prompt_for_preview("Upload") is False


def test_a_long_preview_still_asks_once(answers):
    # The list is summarized for display; that must not add prompts.
    answers.queue.append("y")

    assert prompts.prompt_for_preview("Upload", [str(i) for i in range(500)]) is True
    assert len(answers.prompts) == 1


###########################################################
# Selection
###########################################################

def test_a_selection_returns_its_option(answers):
    answers.queue.append("2")

    assert prompts.prompt_for_selection("Pick", ["a", "b", "c"]) == "b"


def test_the_first_option_is_one(answers):
    # The list is displayed one-based; zero is cancel.
    answers.queue.append("1")

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) == "a"


def test_the_last_option_is_selectable(answers):
    answers.queue.append("3")

    assert prompts.prompt_for_selection("Pick", ["a", "b", "c"]) == "c"


def test_zero_cancels(answers):
    answers.queue.append("0")

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) is None


def test_zero_does_not_cancel_when_cancelling_is_off(answers):
    answers.queue.extend(["0", "1"])

    assert prompts.prompt_for_selection("Pick", ["a", "b"], allow_cancel = False) == "a"


def test_an_out_of_range_selection_is_re_prompted(answers):
    answers.queue.extend(["9", "1"])

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) == "a"
    assert len(answers.prompts) == 2


def test_a_negative_selection_is_re_prompted(answers):
    answers.queue.extend(["-1", "1"])

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) == "a"


def test_a_non_numeric_selection_is_re_prompted(answers):
    answers.queue.extend(["b", "2"])

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) == "b"


def test_an_empty_selection_is_re_prompted(answers):
    answers.queue.extend(["", "1"])

    assert prompts.prompt_for_selection("Pick", ["a", "b"]) == "a"


def test_no_options_selects_nothing(answers):
    assert prompts.prompt_for_selection("Pick", []) is None
    assert answers.prompts == []


def test_a_display_function_does_not_change_the_result(answers):
    answers.queue.append("1")
    options = [{"name": "Chrono Trigger"}]

    assert prompts.prompt_for_selection(
        "Pick", options, display_func = lambda entry: entry["name"]) is options[0]


def test_a_selection_returns_the_original_object(answers):
    answers.queue.append("2")
    options = [{"id": 1}, {"id": 2}]

    assert prompts.prompt_for_selection("Pick", options) is options[1]
