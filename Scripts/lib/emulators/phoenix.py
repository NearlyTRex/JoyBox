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

# Phoenix emulator
class Phoenix(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Phoenix"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Phoenix": {
                "program": {
                    "windows": "Phoenix/windows/PhoenixEmuProject.exe",
                    "linux": "Phoenix/windows/PhoenixEmuProject.exe"
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
        if programs.ShouldProgramBeInstalled("Phoenix", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://archive.org/download/PHX_EMU/ph28jag-win64.zip",
                search_file = "PhoenixEmuProject.exe",
                install_name = "Phoenix",
                install_dir = programs.GetProgramInstallDir("Phoenix", "windows"),
                backups_dir = programs.GetProgramBackupDir("Phoenix", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Phoenix")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Phoenix", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Phoenix", "windows"),
                install_name = "Phoenix",
                install_dir = programs.GetProgramInstallDir("Phoenix", "windows"),
                search_file = "PhoenixEmuProject.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Phoenix")
