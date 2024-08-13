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
        return False

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
        return False

    # Download
    def Download(
        self,
        game_info,
        output_dir = None,
        skip_existing = False,
        force = False,
        verbose = False,
        exit_on_failure = False):
        return False

    # Get info
    def GetInfo(
        self,
        identifier,
        branch = None,
        verbose = False,
        exit_on_failure = False):
        return {}

    # Get versions
    def GetVersions(
        self,
        game_info,
        verbose = False,
        exit_on_failure = False):
        return (None, None)

    # Export save
    def ExportSave(
        self,
        game_info,
        output_dir,
        verbose = False,
        exit_on_failure = False):
        return False

    # Import save
    def ImportSave(
        self,
        game_info,
        input_dir,
        verbose = False,
        exit_on_failure = False):
        return False
