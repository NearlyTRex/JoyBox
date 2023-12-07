# Imports
import os, os.path
import sys

# Base third-party library
class ThirdPartyLibraryBase:

    # Get name
    def GetName():
        return ""

    # Get config
    def GetConfig():
        return {}

    # Download
    def Download(force_downloads = False):
        pass
