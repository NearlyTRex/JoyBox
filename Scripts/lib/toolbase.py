# Imports
import os, os.path
import sys

# Local imports
import config

# Base tool
class ToolBase:

    # Get name
    def GetName(self):
        return ""

    # Get config
    def GetConfig(self):
        return {}

    # Setup
    def Setup(self, setup_params = None):
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        return True

    # Configure
    def Configure(self, setup_params = None):
        return True
