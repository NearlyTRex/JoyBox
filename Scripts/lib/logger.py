# Imports
import os
import sys
import logging
from datetime import datetime

# Local imports
import config
import system
import environment
import fileops

# ANSI color codes for terminal output
class Colors:
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
    LEVEL_COLORS = {
        logging.DEBUG: Colors.GRAY,
        logging.INFO: Colors.GREEN,
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.BRIGHT_RED + Colors.BOLD,
    }

    def __init__(self, fmt, datefmt = None, use_colors = True):
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stdout.isatty()

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
        fileops.make_directory(self.log_dir)

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

    def get_default_log_dir(self):
        return environment.get_log_directory()

    def get_timestamped_filename(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return "%s_%s.log" % (self.name, timestamp)

    def add_console_handler(self):
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(self.level)
        formatter = ColoredFormatter(
            self.DEFAULT_FORMAT,
            self.DEFAULT_DATE_FORMAT,
            use_colors = self.use_colors
        )
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

    def add_file_handler(self):
        log_file = os.path.join(self.log_dir, self.get_timestamped_filename())
        handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
        handler.setLevel(self.level)
        formatter = logging.Formatter(self.DEFAULT_FORMAT, self.DEFAULT_DATE_FORMAT)
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._current_log_file = log_file

    def _format_message(self, message, game_supercategory, game_category, game_subcategory, game_name):
        context = format_game_context(game_supercategory, game_category, game_subcategory, game_name)
        if context:
            return "%s %s" % (context, message)
        return message

    def debug(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.debug(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    def info(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.info(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    def warning(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.warning(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    def error(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.error(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    def critical(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.critical(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    def exception(self, message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
        self._logger.exception(self._format_message(message, game_supercategory, game_category, game_subcategory, game_name))

    @property
    def log_file(self):
        return self._current_log_file

_global_logger = None
def get_logger(name = "output"):
    global _global_logger
    if _global_logger is None:
        _global_logger = Logger(name)
    return _global_logger

def setup_logging(name = "output", log_dir = None, level = logging.DEBUG, use_colors = True):
    global _global_logger
    _global_logger = Logger(
        name = name,
        log_dir = log_dir,
        level = level,
        use_colors = use_colors)
    return _global_logger

def log_info(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().info(message, game_supercategory, game_category, game_subcategory, game_name)

def log_warning(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().warning(message, game_supercategory, game_category, game_subcategory, game_name)

def log_error(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None, quit_program = False):
    get_logger().error(message, game_supercategory, game_category, game_subcategory, game_name)
    if quit_program:
        system.quit_program()

def log_debug(message, game_supercategory = None, game_category = None, game_subcategory = None, game_name = None):
    get_logger().debug(message, game_supercategory, game_category, game_subcategory, game_name)

def log_percent_complete(percent_complete):
    print(">>> Percent complete: %s%% " % percent_complete, end='\r', flush=True)

def log_progress_dot():
    print(".", end="", flush=True)

def log_progress_newline():
    print(flush=True)
