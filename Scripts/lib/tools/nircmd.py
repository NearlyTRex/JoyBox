# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
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
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("NirCmd", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://www.nirsoft.net/utils/nircmd-x64.zip",
                search_file = "nircmdc.exe",
                install_name = "NirCmd",
                install_dir = programs.GetProgramInstallDir("NirCmd", "windows"),
                backups_dir = programs.GetProgramBackupDir("NirCmd", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup NirCmd")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("NirCmd", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("NirCmd", "windows"),
                install_name = "NirCmd",
                install_dir = programs.GetProgramInstallDir("NirCmd", "windows"),
                search_file = "nircmdc.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup NirCmd")
