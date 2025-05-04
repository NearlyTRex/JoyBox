# Imports
import os
import sys
from enum import Enum

# Default config file
DEFAULT_CONFIG_FILE = "JoyBox.ini"

# Environment type
class EnvironmentType(Enum):
    LOCAL_UBUNTU = "local_ubuntu"
    LOCAL_WINDOWS = "local_windows"
    REMOTE_UBUNTU = "remote_ubuntu"
    REMOTE_WINDOWS = "remote_windows"
    def __str__(self):
        return self.name.lower()
