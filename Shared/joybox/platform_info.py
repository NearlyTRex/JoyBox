# Platform and Linux distribution detection.

# Imports
import os
import sys

# Local imports
from joybox import serialization

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

# "windows", "linux" or "macos" for the running OS; None for any other
def get_current_platform():
    if is_windows_platform():
        return "windows"
    if is_linux_platform():
        return "linux"
    if is_mac_platform():
        return "macos"
    return None

###########################################################
# Linux distribution
###########################################################

# The file a Linux distribution describes itself in
OS_RELEASE_FILE = "/etc/os-release"

# Get a field value from /etc/os-release
def get_linux_distro_value(field):
    if not os.path.isfile(OS_RELEASE_FILE):
        return ""
    for line in serialization.read_text_lines(OS_RELEASE_FILE) or []:
        if line.startswith("#"):
            continue
        tokens = line.strip().split("=")
        if len(tokens) == 2 and tokens[0] == field:
            return tokens[1].strip("\"")
    return ""

# Distro NAME from /etc/os-release; empty off Linux or when unset
def get_linux_distro_name():
    return get_linux_distro_value("NAME")

# Distro VERSION from /etc/os-release; empty off Linux or when unset
def get_linux_distro_version():
    return get_linux_distro_value("VERSION")

# Distro ID from /etc/os-release; empty off Linux or when unset
def get_linux_distro_id():
    return get_linux_distro_value("ID")

# Distro ID_LIKE parents from /etc/os-release; empty off Linux or when unset
def get_linux_distro_id_like():
    return get_linux_distro_value("ID_LIKE")

# Whether os-release names Ubuntu in NAME, ID or ID_LIKE, so Ubuntu derivatives count
def is_ubuntu_distro():
    if "ubuntu" in get_linux_distro_name().lower():
        return True
    if "ubuntu" in get_linux_distro_id():
        return True
    if "ubuntu" in get_linux_distro_id_like():
        return True
    return False

# UBUNTU_CODENAME from /etc/os-release, such as noble; empty when unset
def get_ubuntu_codename():
    return get_linux_distro_value("UBUNTU_CODENAME")
