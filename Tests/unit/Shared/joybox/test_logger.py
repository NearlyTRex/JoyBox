# Imports
import io
import logging
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, logger, runtime


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



###########################################################
# Logger instances
###########################################################

@pytest.fixture
def make_logger(tmp_path):
    made = []

    def make(name, **kwargs):
        instance = logger.Logger(name = name, log_dir = str(tmp_path), **kwargs)
        made.append(instance)
        return instance
    yield make
    for instance in made:
        for handler in list(instance._logger.handlers):
            handler.close()
            instance._logger.removeHandler(handler)


def read_log(instance):
    for handler in instance._logger.handlers:
        handler.flush()
    with open(instance.log_file, encoding = "utf-8") as handle:
        return handle.read()


def test_every_level_reaches_the_log_file(make_logger):
    instance = make_logger("probe_levels", console_output = False)

    instance.debug("d")
    instance.info("i")
    instance.warning("w")
    instance.error("e")
    instance.critical("c")
    try:
        raise ValueError("inner")
    except ValueError:
        instance.exception("x")

    text = read_log(instance)
    for level, message in [("DEBUG", "d"), ("INFO", "i"), ("WARNING", "w"),
                           ("ERROR", "e"), ("CRITICAL", "c"), ("ERROR", "x")]:
        assert "%s - %s" % (level, message) in text
    assert "ValueError: inner" in text


def test_a_game_context_prefixes_the_message(make_logger):
    instance = make_logger("probe_context", console_output = False)

    instance.info("found", game_name = "Doom")

    assert "[Doom] found" in read_log(instance)


def test_the_log_file_is_named_after_the_logger(make_logger, tmp_path):
    instance = make_logger("probe_name", console_output = False)

    assert os.path.dirname(instance.log_file) == str(tmp_path)
    assert os.path.basename(instance.log_file).startswith("probe_name_")


def test_a_console_only_logger_has_no_log_file(make_logger):
    instance = make_logger("probe_console", file_output = False)

    assert instance.log_file is None
    assert len(instance._logger.handlers) == 1


def test_a_logger_without_outputs_has_no_handlers(make_logger):
    instance = make_logger("probe_silent", console_output = False, file_output = False)

    assert instance._logger.handlers == []


def test_a_stdout_that_cannot_reconfigure_still_gets_a_handler(make_logger, monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.StringIO())

    instance = make_logger("probe_stringio", file_output = False)
    instance.info("hello")

    assert "hello" in sys.stdout.getvalue()


def test_the_default_log_directory_is_the_runtime_one(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "get_log_directory", lambda: str(tmp_path / "logs"))

    instance = logger.Logger(name = "probe_default", console_output = False, file_output = False)

    assert instance.log_dir == str(tmp_path / "logs")
    assert os.path.isdir(instance.log_dir)


###########################################################
# Colored console output
###########################################################

def make_record(level):
    return logging.LogRecord("probe", level, __file__, 1, "message", None, None)


class FakeTty(io.StringIO):
    def isatty(self):
        return True


def test_a_terminal_gets_colored_level_names(monkeypatch):
    monkeypatch.setattr(sys, "stdout", FakeTty())
    formatter = logger.ColoredFormatter("%(levelname)s %(message)s")
    record = make_record(logging.ERROR)

    assert formatter.format(record) == "%sERROR%s message" % (logger.Colors.RED, logger.Colors.RESET)
    assert record.levelname == "ERROR"


def test_an_unknown_level_is_reset_colored(monkeypatch):
    monkeypatch.setattr(sys, "stdout", FakeTty())
    formatter = logger.ColoredFormatter("%(levelname)s")

    assert formatter.format(make_record(25)).startswith(logger.Colors.RESET)


def test_colors_can_be_turned_off_on_a_terminal(monkeypatch):
    monkeypatch.setattr(sys, "stdout", FakeTty())
    formatter = logger.ColoredFormatter("%(levelname)s", use_colors = False)

    assert formatter.format(make_record(logging.ERROR)) == "ERROR"


def test_a_pipe_gets_plain_level_names(monkeypatch):
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    formatter = logger.ColoredFormatter("%(levelname)s")

    assert formatter.format(make_record(logging.ERROR)) == "ERROR"


###########################################################
# Module-level helpers
###########################################################

@pytest.fixture
def global_logger(tmp_path, monkeypatch):
    monkeypatch.setattr(logger, "_global_logger", None)
    instance = logger.setup_logging(name = "probe_global", log_dir = str(tmp_path), use_colors = False)
    yield instance
    for handler in list(instance._logger.handlers):
        handler.close()
        instance._logger.removeHandler(handler)


def test_setup_logging_installs_the_global_logger(global_logger):
    assert logger.get_logger() is global_logger
    assert global_logger.name == "probe_global"


def test_setup_logging_defaults_the_name_to_the_script(tmp_path, monkeypatch):
    monkeypatch.setattr(logger, "_global_logger", None)
    monkeypatch.setattr(sys, "argv", ["/bin/probe_script.py"])

    instance = logger.setup_logging(log_dir = str(tmp_path))
    try:
        assert instance.name == "probe_script"
    finally:
        for handler in list(instance._logger.handlers):
            handler.close()
            instance._logger.removeHandler(handler)


def test_debug_and_header_lines_reach_the_log(global_logger):
    logger.log_debug("deep")
    logger.log_header("Title", width = 5)

    text = read_log(global_logger)
    assert "DEBUG - deep" in text
    assert text.count("INFO - =====") == 2
    assert "INFO - Title" in text


def test_quitting_errors_exit(global_logger):
    with pytest.raises(SystemExit):
        logger.log_error_and_quit("fatal")


def test_progress_markers_print_inline(capsys):
    logger.log_percent_complete(50)
    logger.log_progress_dot()
    logger.log_progress_newline()

    assert capsys.readouterr().out == ">>> Percent complete: 50% \r.\n"


###########################################################
# Raw command output
###########################################################

def test_raw_output_is_written_verbatim(capsys):
    logger.log_output("line one\n")

    assert capsys.readouterr().out == "line one\n"


def test_recorded_output_lands_in_one_output_log(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "get_log_directory", lambda: str(tmp_path))
    monkeypatch.setattr(logger, "_output_recorder_ready", False)
    recorder = logging.getLogger(logger.OUTPUT_LOGGER_NAME)
    existing = list(recorder.handlers)
    try:
        logger.record_output("first")
        logger.record_output("second")
        added = [handler for handler in recorder.handlers if handler not in existing]
        assert len(added) == 1
        added[0].flush()
        (log_file,) = tmp_path.glob("output_*.log")
        assert log_file.read_text().splitlines() == ["first", "second"]
    finally:
        for handler in recorder.handlers[len(existing):]:
            handler.close()
            recorder.removeHandler(handler)
