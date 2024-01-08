# Imports
import os
import sys

# Local imports
import environment
if environment.IsWindowsPlatform():
    from packages.windows.winget import *
