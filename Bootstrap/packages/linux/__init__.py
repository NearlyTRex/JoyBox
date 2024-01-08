# Imports
import os
import sys

# Local imports
import environment
if environment.IsLinuxPlatform():
    if "ubuntu" in environment.GetLinuxDistroName().lower():
        from packages.linux.ubuntu import *
