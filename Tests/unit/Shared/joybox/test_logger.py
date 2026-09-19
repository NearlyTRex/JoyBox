# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, logger


###########################################################
# Game context
#
# Prefixes log lines so a message can be traced back to one game across a
# sweep over thousands of them.
###########################################################

def test_a_full_context_carries_every_part():
    context = logger.format_game_context(
        game_supercategory = config.Supercategory.ROMS,
        game_category = config.Category.NINTENDO,
        game_subcategory = config.Subcategory.NINTENDO_64,
        game_name = "Super Mario 64")

    for part in ["Roms", "Nintendo", "Nintendo 64", "Super Mario 64"]:
        assert f"[{part}]" in context


def test_context_parts_are_ordered_broad_to_narrow():
    context = logger.format_game_context(
        game_supercategory = config.Supercategory.ROMS,
        game_category = config.Category.NINTENDO,
        game_name = "Super Mario 64")

    assert context.index("Roms") < context.index("Nintendo") < context.index("Super Mario 64")


def test_an_omitted_part_is_skipped():
    context = logger.format_game_context(game_name = "Super Mario 64")

    assert context == "[Super Mario 64]"


def test_no_parts_yields_no_context():
    assert logger.format_game_context() == ""


def test_every_part_is_bracketed():
    context = logger.format_game_context(
        game_supercategory = config.Supercategory.ROMS,
        game_name = "Game")

    assert context.count("[") == context.count("]") == 2


def test_a_context_has_no_separators():
    # The parts abut so the prefix stays compact on every line.
    context = logger.format_game_context(
        game_supercategory = config.Supercategory.ROMS,
        game_category = config.Category.NINTENDO)

    assert "][" in context
    assert " " not in context.replace("Nintendo", "").replace("Roms", "")


###########################################################
# Script name
###########################################################

def test_the_script_name_comes_from_argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/path/to/build_game_json_files.py"])

    assert logger.get_script_name() == "build_game_json_files"


def test_the_extension_is_dropped(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["tool.py"])

    assert logger.get_script_name() == "tool"


def test_a_name_without_an_extension_survives(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/usr/bin/tool"])

    assert logger.get_script_name() == "tool"


def test_an_empty_argv_falls_back(monkeypatch):
    # The log file is named after this, so it can never be empty.
    monkeypatch.setattr(sys, "argv", [])

    assert logger.get_script_name() == "output"


def test_a_blank_argv_entry_falls_back(monkeypatch):
    monkeypatch.setattr(sys, "argv", [""])

    assert logger.get_script_name() == "output"


def test_a_leading_dot_is_kept(monkeypatch):
    # splitext treats a leading dot as a dotfile name, not an extension.
    monkeypatch.setattr(sys, "argv", [".py"])

    assert logger.get_script_name() == ".py"


def test_the_script_name_is_usable_as_a_filename(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["/path/to/tool.py"])
    name = logger.get_script_name()

    assert os.sep not in name
    assert name


###########################################################
# Logging calls
###########################################################

@pytest.mark.parametrize("level", ["log_info", "log_warning", "log_error"])
def test_every_level_accepts_a_message(level):
    # These are called from every script; none may raise on a plain string.
    getattr(logger, level)("a message")


def test_logging_accepts_an_exception():
    logger.log_error(RuntimeError("boom"))


def test_logging_accepts_a_non_string():
    logger.log_info(12345)
