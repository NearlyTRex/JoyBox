# Imports
import os, os.path
import sys

# Local imports
import config

# Base tool
class ToolBase:

    # Get name
    def get_name(self):
        return ""

    # Get config
    def get_config(self):
        return {}

    # Setup
    def setup(self, setup_params = None):
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        return True

    # Configure
    def configure(self, setup_params = None):
        return True
