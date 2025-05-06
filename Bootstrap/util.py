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
        pretend_run = False,
        exit_on_failure = True,
        skip_existing = False):
        self.verbose = verbose
        self.pretend_run = pretend_run
        self.exit_on_failure = exit_on_failure
        self.skip_existing = skip_existing

    def Copy(self):
        return copy.deepcopy(self)

    def SetVerbose(self, verbose):
        self.verbose = verbose
        return self

    def SetPretendRun(self, pretend_run):
        self.pretend_run = pretend_run
        return self

    def SetExitOnFailure(self, exit_on_failure):
        self.exit_on_failure = exit_on_failure
        return self

    def SetSkipExisting(self, skip_existing):
        self.skip_existing = skip_existing
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

    def Copy(self):
        return copy.deepcopy(self)

    def SetCurrentWorkingDirectory(self, cwd):
        self.cwd = cwd
        return self

    def SetEnvironment(self, env):
        self.env = env
        return self

    def SetShell(self, shell):
        self.shell = shell
        return self

    def SetCreationFlags(self, creationflags):
        self.creationflags = creationflags
        return self

    def SetStdout(self, stdout):
        self.stdout = stdout
        return self

    def SetStderr(self, stderr):
        self.stderr = stderr
        return self

    def SetIncludeStderr(self, include_stderr):
        self.include_stderr = include_stderr
        return self

###########################################################
# System
###########################################################
def IsWindowsPlatform():
    return sys.platform.startswith("win32")

def IsLinuxPlatform():
    return sys.platform.startswith("linux")

def QuitProgram(exit_code = -1):
    sys.exit(exit_code)

def SleepProgram(seconds):
    time.sleep(seconds)

def GetCurrentTime():
    return time.time()

###########################################################
# Logging
###########################################################
def SetupLogging(log_file = "output.log", log_format = "%(asctime)s - %(levelname)s - %(message)s", log_level = logging.DEBUG):
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

def LogInfo(message):
    logger = logging.getLogger(__name__)
    logger.info(message)

def LogWarning(message):
    logger = logging.getLogger(__name__)
    logger.warning(message)

def LogError(message):
    logger = logging.getLogger(__name__)
    logger.error(message)

def LogErrorAndQuit(message):
    LogError(message)
    QuitProgram()

###########################################################
# Paths
###########################################################
def IsPathValid(path):
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

def IsExcludedPath(path, excludes = []):
    for exclude in excludes:
        if any(exclude in part for part in path.split(os.sep)):
            return True
    return False

###########################################################
# Input prompts
###########################################################
def PromptForValue(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        value = default_value
    return value

def PromptForInt(description, default_value = None):
    while True:
        value = PromptForValue(description, default_value)
        if not isinstance(value, str):
            continue
        if value.isdigit():
            return int(value)
        else:
            LogWarning("Entered value '%s' was not a valid integer, please try again" % value)

def PromptForChoice(description, choices = [], default_value = None):
    while True:
        value = PromptForValue(description, default_value)
        if not isinstance(value, str):
            continue
        if value.strip().lower() in choices:
            return value
        else:
            LogWarning("Entered value '%s' was not a valid choice, please try again" % value)

def PromptForFile(description, default_value = None):
    while True:
        value = PromptForValue(description, default_value)
        if not isinstance(value, str):
            continue
        if os.path.exists(os.path.realpath(value)):
            return value
        else:
            LogWarning("Entered value '%s' was not a valid file, please try again" % value)

###########################################################
# Distro
###########################################################
def GetLinuxDistroValue(field):
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

def GetLinuxDistroName():
    return GetLinuxDistroValue("NAME")

def GetLinuxDistroVersion():
    return GetLinuxDistroValue("VERSION")

def GetLinuxDistroId():
    return GetLinuxDistroValue("ID")

def GetLinuxDistroIdLike():
    return GetLinuxDistroValue("ID_LIKE")

def IsUbuntuDistro():
    if "ubuntu" in GetLinuxDistroName().lower():
        return True
    elif "ubuntu" in GetLinuxDistroId():
        return True
    elif "ubuntu" in GetLinuxDistroIdLike():
        return True
    return False

def GetUbuntuCodename():
    return GetLinuxDistroValue("UBUNTU_CODENAME")
