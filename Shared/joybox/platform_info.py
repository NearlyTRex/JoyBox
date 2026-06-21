# Platform and Linux distribution detection.

# Imports
import os
import sys

###########################################################
# Platform
###########################################################

# Determine if windows platform
def is_windows_platform():
    return sys.platform.startswith("win32")

# Determine if linux platform
def is_linux_platform():
    return sys.platform.startswith("linux")

# Determine if mac platform
def is_mac_platform():
    return sys.platform.startswith("darwin")

# Determine if unix platform
def is_unix_platform():
    return is_mac_platform() or is_linux_platform()

# Determine if wine platform
def is_wine_platform():
    return is_linux_platform()

# Determine if sandboxie platform
def is_sandboxie_platform():
    return is_windows_platform()

# Get current platform
def get_current_platform():
    if is_windows_platform():
        return "windows"
    elif is_linux_platform():
        return "linux"
    elif is_mac_platform():
        return "macos"
    return None

###########################################################
# Linux distribution
###########################################################

# Get a field value from /etc/os-release
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
