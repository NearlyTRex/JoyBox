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
import paramiko
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

    def copy(self):
        return copy.deepcopy(self)

    def set_verbose(self, verbose):
        self.verbose = verbose
        return self

    def set_pretend_run(self, pretend_run):
        self.pretend_run = pretend_run
        return self

    def set_exit_on_failure(self, exit_on_failure):
        self.exit_on_failure = exit_on_failure
        return self

    def set_skip_existing(self, skip_existing):
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

    def copy(self):
        return copy.deepcopy(self)

    def set_cwd(self, cwd):
        self.cwd = cwd
        return self

    def set_env(self, env):
        self.env = env
        return self

    def set_shell(self, shell):
        self.shell = shell
        return self

    def set_creationflags(self, creationflags):
        self.creationflags = creationflags
        return self

    def set_stdout(self, stdout):
        self.stdout = stdout
        return self

    def set_stderr(self, stderr):
        self.stderr = stderr
        return self

    def set_include_stderr(self, include_stderr):
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
# Configuration files
###########################################################
def LoadConfigFile(src):
    try:
        config = configparser.ConfigParser(interpolation = None)
        config.read(src)
        config_dict = {}
        for section in config.sections():
            section_dict = {}
            for key, value in config.items(section):
                if value.lower() in ["true", "false"]:
                    section_dict[key] = config.getboolean(section, key)
                else:
                    section_dict[key] = value
            config_dict[section] = section_dict
        return config_dict
    except Exception as e:
        LogError("Error reading the config file '%s'" % src)
        LogError(e)
        return None

def InitializeConfigFile(src, default_config):

    # Load current config if it exists
    config_exists = os.path.isfile(src)
    config_dict = LoadConfigFile(src) if config_exists else {}

    # Add in the default config sections
    updated = False
    full_config = configparser.ConfigParser(interpolation = None)
    for section, defaults in default_config.items():
        if section not in config_dict:
            config_dict[section] = {}
        if not full_config.has_section(section):
            full_config.add_section(section)
        for key, default_value in defaults.items():
            if key not in config_dict[section]:
                config_dict[section][key] = PromptForValue(key, default_value)
                updated = True
            full_config.set(section, key, str(config_dict[section][key]))

    # Write config back to file
    if updated or not config_exists:
        with open(ini_path, "w") as f:
            full_config.write(f)
    return config_dict

###########################################################
# Networking
###########################################################
def FetchJson(url, flags = RunFlags()):
    try:
        if flags.verbose:
            LogInfo("Fetching JSON from %s" % url)
        with urllib.request.urlopen(url) as response:
            data = response.read()
            return json.loads(data)
        return None
    except Exception as e:
        if flags.exit_on_failure:
            LogError("Error fetching JSON from %s" % url)
            LogError(e)
            QuitProgram()
        return None

def CopyFilesToRemoteHost(
    hostname,
    username,
    private_key_str,
    local_path,
    remote_path,
    excludes = []):
    try:
        # Connect to remote
        transport = paramiko.Transport((hostname, 22))
        private_key = paramiko.RSAKey.from_private_key(io.StringIO(private_key_str))
        transport.connect(username = username, pkey = private_key)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp_lock = threading.Lock()

        # Gather all files and ensure remote dirs
        file_tasks = []
        for dirpath, dirnames, filenames in os.walk(local_path):
            if IsExcludedPath(os.path.relpath(dirpath, local_path), excludes = excludes):
                continue

            # Get remote directory
            if dirpath == local_path:
                remote_dir = remote_path
            else:
                remote_dir = os.path.join(remote_path, os.path.relpath(dirpath, local_path))

            # Ensure the remote directory exists
            LogInfo(f"Making remote directory: {remote_dir}")
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                sftp.mkdir(remote_dir)

            # Collect files to copy
            for filename in filenames:
                local_file_path = os.path.join(dirpath, filename)
                remote_file_path = os.path.join(remote_dir, filename)
                file_tasks.append((local_file_path, remote_file_path))

        # Upload files in parallel
        def upload_file(task):
            local_file, remote_file = task
            try:
                with sftp_lock:
                    LogInfo(f"Copying file to remote: {local_file} to {remote_file}")
                    sftp.put(local_file, remote_file)
            except Exception as e:
                LogError(f"Failed to copy file {local_file} to {remote_file}: {e}")

        # Start uploads
        with concurrent.futures.ThreadPoolExecutor(max_workers = 8) as executor:
            executor.map(upload_file, file_tasks)
        sftp.close()
        transport.close()
        return True
    except Exception as e:
        LogError(f"Failed to copy {local_path} to {remote_path}")
        LogError(e)
        LogError(traceback.format_exc())
        return False

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
