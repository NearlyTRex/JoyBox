# Imports
import os
import sys

# Local imports
import environment

# Relative imports
from . import winget
from . import ubuntu

# Setup
def Setup(ini_values = {}):
    if environment.IsWindowsPlatform():
        winget.Setup(ini_values)
    elif environment.IsLinuxPlatform():
        if environment.IsUbuntuDistro():
            ubuntu.Setup(ini_values)
