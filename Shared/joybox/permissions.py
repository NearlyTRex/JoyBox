# Imports
import importlib
import os

# Local imports
from joybox import platform_info

# Get pyuac, imported on first use
def _get_pyuac():
    return importlib.import_module("pyuac")

###########################################################
# Root access
###########################################################

# Determine if user is root
def is_user_root():
    if platform_info.is_windows_platform():
        try:
            pyuac = _get_pyuac()
        except ImportError:
            return False
        try:
            return pyuac.isUserAdmin()
        except OSError:
            return False
    else:
        return os.getuid() == 0

# Call func elevated: on Windows relaunch through UAC when not admin, otherwise call it directly without elevating
def run_as_root(func):
    if not callable(func):
        return
    if platform_info.is_windows_platform():
        try:
            pyuac = _get_pyuac()
            if not pyuac.isUserAdmin():
                pyuac.runAsAdmin()
            else:
                func()
        except ModuleNotFoundError:
            func()
    else:
        func()
