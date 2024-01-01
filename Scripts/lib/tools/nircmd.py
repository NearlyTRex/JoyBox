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

# NirCmd tool
class NirCmd(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "NirCmd"

    # Get config
    def GetConfig(self):
        return {
            "NirCmd": {
                "program": {
                    "windows": "NirCmd/windows/nircmdc.exe",
                    "linux": "NirCmd/windows/nircmdc.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("NirCmd", "windows"):
            success = network.DownloadGeneralRelease(
                archive_url = "https://www.nirsoft.net/utils/nircmd-x64.zip",
                search_file = "nircmdc.exe",
                install_name = "NirCmd",
                install_dir = programs.GetProgramInstallDir("NirCmd", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup NirCmd")
