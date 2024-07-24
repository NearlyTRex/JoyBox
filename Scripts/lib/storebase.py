# Imports
import os, os.path
import sys

# Local imports
import system
from tools import ludusavimanifest

# Base store
class StoreBase:

    # Constructor
    def __init__(self):
        self.manifest = None

    # Get name
    def GetName(self):
        return ""

    # Load manifest
    def LoadManifest(self, verbose = False, exit_on_failure = False):
        self.manifest = system.ReadYamlFile(
            src = ludusavimanifest.GetManifest(),
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Login
    def Login(
        self,
        verbose = False,
        exit_on_failure = False):
        pass

    # Fetch
    def Fetch(
        self,
        identifier,
        output_dir,
        output_name = None,
        branch = None,
        clean_output = False,
        verbose = False,
        exit_on_failure = False):
        pass

    # Download
    def Download(
        self,
        json_file,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        exit_on_failure = False):
        pass

    # Get info
    def GetInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):
        pass

    # Get versions
    def GetVersions(
        self,
        json_file,
        verbose = False,
        exit_on_failure = False):
        pass
