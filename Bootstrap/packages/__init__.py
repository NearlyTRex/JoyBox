# Imports
import os
import sys

# Local imports
import environment
if environment.IsWindowsPlatform():
    from packages.windows import *
elif environment.IsLinuxPlatform():
    from packages.linux import *
from packages.python import *
