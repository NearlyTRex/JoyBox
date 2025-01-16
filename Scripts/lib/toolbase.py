# Imports
import os, os.path
import sys

# Base tool
class ToolBase:

    # Get name
    def GetName(self):
        return ""

    # Get config
    def GetConfig(self):
        return {}

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):
        return True
