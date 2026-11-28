# Imports
import enum
import functools
import os
import sys
import logging
import types
from datetime import datetime

# Local imports
from joybox import runtime, terminal

# ANSI color codes for terminal output
class Colors(enum.StrEnum):
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[90m"

    # Bright variants
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"

# Formatter that adds colors to console output based on log level
class ColoredFormatter(logging.Formatter):
    LEVEL_COLORS = types.MappingProxyType({
        logging.DEBUG: Colors.GRAY,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BRIGHT_RED + Colors.BOLD,
    })

    def __init__(self, fmt, datefmt = None, use_colors = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

    # The record formatted with its level name wrapped in the level's ANSI color, when colors are on
    def format(self, record):
        if self.use_colors:
            original_levelname = record.levelname
            color = self.LEVEL_COLORS.get(record.levelno, Colors.RESET)
            record.levelname = f"{color}{original_levelname}{Colors.RESET}"
            result = super().format(record)
            record.levelname = original_levelname
            return result
        return super().format(record)

# Format game context prefix
def format_game_context(
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_name = None):
    context = ""
    if game_supercategory:
        context += "[%s]" % game_supercategory.val()
    if game_category:
        context += "[%s]" % game_category.val()
    if game_subcategory:
        context += "[%s]" % game_subcategory.val()
    if game_name:
        context += "[%s]" % game_name
    return context

# Default logger
class Logger:
    DEFAULT_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
    DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

    def __init__(
        self,
        name = "output",
        log_dir = None,
        level = logging.DEBUG,
        use_colors = True,
        console_output = True,
        file_output = True):

        # Init logging info
        self.name = name
        self.log_dir = log_dir or self.get_default_log_dir()
        self.level = level
        self.use_colors = use_colors
        self._current_log_file = None

        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok = True)

        # Create the underlying logger
        self._logger = logging.getLogger("logs.%s" % name)
        self._logger.setLevel(level)
        self._logger.propagate = False

        # Clear any existing handlers
        self._logger.handlers.clear()

        # Add handlers
        if console_output:
            self.add_console_handler()
        if file_output:
            self.add_file_handler()

    # The runtime's log directory, used when none is given
    def get_default_log_dir(self):
        return runtime.get_log_directory()

    # Log file name: the logger name plus a YYYYmmdd_HHMMSS timestamp
    def get_timestamped_filename(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return "%s_%s.log" % (self.name, timestamp)

    # Attach a colored stdout handler at the logger's level, switching stdout to backslash-escape unencodable text
    def add_console_handler(self):
        # A replaced stdout, as under a test runner, may not be reconfigurable
        if callable(getattr(sys.stdout, "reconfigure", None)):
            sys.stdout.reconfigure(errors="backslashreplace")
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(self.level)
        formatter = ColoredFormatter(
            self.DEFAULT_FORMAT,
            self.DEFAULT_DATE_FORMAT,
            use_colors = self.use_colors
        )
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    # Attach a handler writing a fresh timestamped log file in the log directory, and remember its path
    def add_file_handler(self):
        log_file = os.path.join(self.log_dir, self.get_timestamped_filename())
        handler = logging.FileHandler(log_file, mode="w", encoding="utf-8", errors="backslashreplace")
        handler.setLevel(self.level)
        formatter = logging.Formatter(self.DEFAULT_FORMAT, self.DEFAULT_DATE_FORMAT)
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._current_log_file = log_file

    def _format_message(self, message, game_supercategory, game_category, game_subcategory, game_name):
        context = format_game_context(game_supercategory, game_category, game_subcategory, game_name)
        if context:
            return escape_surrogates("%s %s" % (context, message))
        return escape_surrogates(str(message))

    # Log at DEBUG level, prefixed with the bracketed game context when given
    def debug(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.debug(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Log at INFO level, prefixed with the bracketed game context when given
    def info(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.info(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Log at WARNING level, prefixed with the bracketed game context when given
    def warning(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.warning(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Log at ERROR level, prefixed with the bracketed game context when given
    def error(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.error(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Log at CRITICAL level, prefixed with the bracketed game context when given
    def critical(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.critical(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Log at ERROR level with the current traceback, prefixed with the bracketed game context when given
    def exception(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.exception(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    # Path of the file this logger writes; None without a file handler
    @property
    def log_file(self):
        return self._current_log_file

# Escape surrogates
# Undecodable filename bytes reach Python as lone surrogates, which no utf-8 handler can write
def escape_surrogates(text):
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")

# The process-wide logger, made on first use or replaced by setup_logging
_state = types.SimpleNamespace(logger = None)

# The process-wide logger, created with console and file output on first use
def get_logger(name = "output"):
    if _state.logger is None:
        _state.logger = Logger(name)
    return _state.logger

# Base name of the running script without its extension; "output" when there is none
def get_script_name():
    if sys.argv and sys.argv[0]:
        return os.path.splitext(os.path.basename(sys.argv[0]))[0] or "output"
    return "output"

# Replace the process-wide logger with one named after the script unless a name is given
def setup_logging(name = None, log_dir = None, level = logging.DEBUG, use_colors = True):
    if name is None:
        name = get_script_name()
    _state.logger = Logger(
        name = name,
        log_dir = log_dir,
        level = level,
        use_colors = use_colors)
    return _state.logger

# Info message through the process-wide logger
def log_info(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().info(message, game_supercategory, game_category, game_subcategory, game_name)

# Warning message through the process-wide logger
def log_warning(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().warning(message, game_supercategory, game_category, game_subcategory, game_name)

# Error message through the process-wide logger, quitting the program when asked
def log_error(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None, quit_program = False):
    get_logger().error(message, game_supercategory, game_category, game_subcategory, game_name)
    if quit_program:
        runtime.quit_program()

# Debug message through the process-wide logger
def log_debug(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().debug(message, game_supercategory, game_category, game_subcategory, game_name)

# Error message through the process-wide logger, then quit the program
def log_error_and_quit(message):
    log_error(message, quit_program = True)

# Info message framed above and below by lines of equals signs
def log_header(message, width = 60):
    log_info("=" * width)
    log_info(message)
    log_info("=" * width)

# Overwrite the terminal line with a percent-complete readout
def log_percent_complete(percent_complete):
    terminal.write(">>> Percent complete: %s%% \r" % percent_complete)

# Write a single dot to the terminal, with no newline
def log_progress_dot():
    terminal.write(".")

# End a run of progress dots or percent readouts with a newline
def log_progress_newline():
    terminal.write("\n")

###########################################################
# Raw command-output streaming
###########################################################
# Used to stream live subprocess output to the console and record it verbatim
# (no level/timestamp prefix) to a dedicated output log.

OUTPUT_LOGGER_NAME = "joybox.output"

# Write text straight to stdout and flush, with no level or timestamp
def log_output(text):
    sys.stdout.write(text)
    sys.stdout.flush()

# Set up the output recorder once, on the first line recorded
@functools.cache
def _ensure_output_recorder():
    recorder = logging.getLogger(OUTPUT_LOGGER_NAME)
    recorder.setLevel(logging.DEBUG)
    recorder.propagate = False
    log_dir = runtime.get_log_directory()
    os.makedirs(log_dir, exist_ok = True)
    log_file = os.path.join(log_dir, "output_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"))
    handler = logging.FileHandler(log_file, mode = "a", encoding = "utf-8", errors = "backslashreplace")
    handler.setFormatter(logging.Formatter("%(message)s"))
    recorder.addHandler(handler)
    return recorder

# Append a line verbatim to this run's output log file
def record_output(line):
    _ensure_output_recorder().info(line)
