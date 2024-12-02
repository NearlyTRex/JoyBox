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
        pass

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):
        pass

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):
        pass
