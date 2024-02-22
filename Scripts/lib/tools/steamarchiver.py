# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# SteamArchiver tool
class SteamArchiver(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "SteamArchiver"

    # Get config
    def GetConfig(self):
        return {

            # SteamArchiver
            "SteamArchiver": {
                "program": "SteamArchiver/depot_archiver.py"
            },

            # SteamExtractor
            "SteamExtractor": {
                "program": "SteamArchiver/depot_extractor.py"
            },

            # SteamGetKeys
            "SteamGetKeys": {
                "program": "SteamArchiver/get_depot_keys.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("SteamArchiver"):
            success = network.DownloadGitUrl(
                url = "https://git.sr.ht/~blowry/steamarchiver",
                output_dir = programs.GetLibraryInstallDir("SteamArchiver"),
                recursive = True,
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SteamArchiver")
