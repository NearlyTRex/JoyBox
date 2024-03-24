# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# BGB emulator
class BGB(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BGB"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "BGB": {
                "program": {
                    "windows": "BGB/windows/bgb.exe",
                    "linux": "BGB/windows/bgb.exe"
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
        if programs.ShouldProgramBeInstalled("BGB", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://bgb.bircd.org/bgb.zip",
                search_file = "bgb.exe",
                install_name = "BGB",
                install_dir = programs.GetProgramInstallDir("BGB", "windows"),
                backups_dir = programs.GetProgramBackupDir("BGB", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BGB")
