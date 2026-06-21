import os
import sys
import copy
import time
import logging

# Local imports
import joyboxshared
from joybox import runtime

###########################################################
# Run flags
###########################################################
class RunFlags:
    def __init__(
        self,
        verbose = True,
        force = False,
        pretend_run = False,
        exit_on_failure = True,
        skip_existing = False):
        self.verbose = verbose
        self.force = force
        self.pretend_run = pretend_run
        self.exit_on_failure = exit_on_failure
        self.skip_existing = skip_existing

    def copy(self):
        return copy.deepcopy(self)

    def set(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"RunFlags has no attribute '{key}'")
        return self

###########################################################
# Run options
###########################################################
class RunOptions:
    def __init__(
        self,
        cwd = None,
        env = None,
        shell = False,
        creationflags = 0,
        stdout = None,
        stderr = None,
        include_stderr = False):
        self.cwd = cwd
        if not env:
            env = {}
        self.env = env
        self.shell = shell
        self.creationflags = creationflags
        self.stdout = stdout
        self.stderr = stderr
        self.include_stderr = include_stderr

    def copy(self):
        return copy.deepcopy(self)

    def set(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise AttributeError(f"RunFlags has no attribute '{key}'")
        return self

###########################################################
# Logging
###########################################################
# Bootstrap logger
OUTPUT_LOGGER_NAME = "joybox.output"

def setup_logging(log_file = None, log_format = "%(asctime)s - %(levelname)s - %(message)s", log_level = logging.DEBUG):
    log_dir = runtime.get_log_directory()
    os.makedirs(log_dir, exist_ok = True)
    if log_file is None:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"bootstrap_{timestamp}.log")
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    formatter = logging.Formatter(log_format)
    file_logger = logging.FileHandler(log_file)
    file_logger.setLevel(log_level)
    file_logger.setFormatter(formatter)
    console_logger = logging.StreamHandler()
    console_logger.setLevel(log_level)
    console_logger.setFormatter(formatter)
    logger.addHandler(file_logger)
    logger.addHandler(console_logger)
    output_logger = logging.getLogger(OUTPUT_LOGGER_NAME)
    output_logger.setLevel(log_level)
    output_logger.propagate = False
    output_file_logger = logging.FileHandler(log_file)
    output_file_logger.setLevel(log_level)
    output_file_logger.setFormatter(logging.Formatter("%(message)s"))
    output_logger.addHandler(output_file_logger)

def log_info(message):
    logger = logging.getLogger(__name__)
    logger.info(message)

def log_output(text):
    sys.stdout.write(text)
    sys.stdout.flush()

def record_output(line):
    logging.getLogger(OUTPUT_LOGGER_NAME).info(line)

def log_warning(message):
    logger = logging.getLogger(__name__)
    logger.warning(message)

def log_error(message):
    logger = logging.getLogger(__name__)
    logger.error(message)

def log_error_and_quit(message):
    log_error(message)
    runtime.quit_program()

###########################################################
# Repo
###########################################################
def get_repo_root(config, expand = False):
    scripts_dir = config.get_value("UserData.Dirs", "scripts_dir") if config else None
    root = scripts_dir.replace("/Scripts", "") if scripts_dir else "$HOME/Repositories/JoyBox"
    return os.path.expandvars(root) if expand else root
