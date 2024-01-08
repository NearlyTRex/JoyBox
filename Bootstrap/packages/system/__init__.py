# Imports
import os
import sys

# Local imports
import environment
if environment.IsWindowsPlatform():
    from packages.system.winget import *
elif environment.IsLinuxPlatform():
    if "ubuntu" in environment.GetLinuxDistroName().lower():
        from packages.system.ubuntu import *
