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
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("BGB", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://bgb.bircd.org/bgb.zip",
                search_file = "bgb.exe",
                install_name = "BGB",
                install_dir = programs.GetProgramInstallDir("BGB", "windows"),
                backups_dir = programs.GetProgramBackupDir("BGB", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup BGB")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BGB", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BGB", "windows"),
                install_name = "BGB",
                install_dir = programs.GetProgramInstallDir("BGB", "windows"),
                search_file = "bgb.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup BGB")
                return False
        return True
