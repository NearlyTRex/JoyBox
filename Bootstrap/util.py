import os
import sys
import re
import io
import copy
import errno
import time
import json
import pathlib
import logging
import configparser
import urllib.request
import traceback
import threading
import concurrent.futures

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
# System
###########################################################
def is_windows_platform():
    return sys.platform.startswith("win32")

def is_linux_platform():
    return sys.platform.startswith("linux")

def quit_program(exit_code = -1):
    sys.exit(exit_code)

def sleep_program(seconds):
    time.sleep(seconds)

def get_current_time():
    return time.time()

###########################################################
# Logging
###########################################################
def setup_logging(log_file = None, log_format = "%(asctime)s - %(levelname)s - %(message)s", log_level = logging.DEBUG):
    if log_file is None:
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(os.path.expanduser("~"), f"joybox_bootstrap_{timestamp}.log")
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

def log_info(message):
    logger = logging.getLogger(__name__)
    logger.info(message)

def log_warning(message):
    logger = logging.getLogger(__name__)
    logger.warning(message)

def log_error(message):
    logger = logging.getLogger(__name__)
    logger.error(message)

def log_error_and_quit(message):
    log_error(message)
    quit_program()

###########################################################
# Paths
###########################################################
def is_path_valid(path):
    try:
        if not isinstance(path, str) or not path or len(path) == 0:
            return False
        if os.name == "nt":
            drive, path = os.path.splitdrive(path)
            if not os.path.isdir(drive):
                drive = os.environ.get("SystemDrive", "C:")
            if not os.path.isdir(drive):
                drive = ""
        else:
            drive = ""
        parts = pathlib.Path(path).parts
        check_list = [os.path.join(*parts), *parts]
        for x in check_list:
            try:
                os.lstat(drive + x)
            except OSError as e:
                if hasattr(e, "winerror") and e.winerror == 123:
                    return False
                elif e.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                    return False
    except TypeError:
        return False
    else:
        return True

def is_exclude_path(path, excludes = []):
    for exclude in excludes:
        if any(exclude in part for part in path.split(os.sep)):
            return True
    return False

###########################################################
# Input prompts
###########################################################
def prompt_for_value(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        value = default_value
    return value

def prompt_for_int(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if not isinstance(value, str):
            continue
        if value.isdigit():
            return int(value)
        else:
            log_warning("Entered value '%s' was not a valid integer, please try again" % value)

def prompt_for_choice(description, choices = [], default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if not isinstance(value, str):
            continue
        if value.strip().lower() in choices:
            return value
        else:
            log_warning("Entered value '%s' was not a valid choice, please try again" % value)

def prompt_for_file(description, default_value = None):
    while True:
        value = prompt_for_value(description, default_value)
        if not isinstance(value, str):
            continue
        if os.path.exists(os.path.realpath(value)):
            return value
        else:
            log_warning("Entered value '%s' was not a valid file, please try again" % value)

###########################################################
# Distro
###########################################################
def get_linux_distro_value(field):
    if os.path.isfile("/etc/os-release"):
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f.readlines():
                if line.startswith("#"):
                    continue
                tokens = line.strip().split("=")
                if len(tokens) == 2:
                    if tokens[0] == field:
                        return tokens[1].strip("\"")
    return ""

def get_linux_distro_name():
    return get_linux_distro_value("NAME")

def get_linux_distro_version():
    return get_linux_distro_value("VERSION")

def get_linux_distro_id():
    return get_linux_distro_value("ID")

def get_linux_distro_id_like():
    return get_linux_distro_value("ID_LIKE")

def is_ubuntu_distro():
    if "ubuntu" in get_linux_distro_name().lower():
        return True
    elif "ubuntu" in get_linux_distro_id():
        return True
    elif "ubuntu" in get_linux_distro_id_like():
        return True
    return False

def get_ubuntu_codename():
    return get_linux_distro_value("UBUNTU_CODENAME")
