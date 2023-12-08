# Imports
import os, os.path
import sys

# Base third-party library
class ThirdPartyLibraryBase:

    # Get name
    def GetName(self):
        return ""

    # Get config
    def GetConfig(self):
        return {}

    # Download
    def Download(self, force_downloads = False):
        pass
