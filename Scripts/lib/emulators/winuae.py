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

# WinUAE emulator
class WinUAE(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "WinUAE"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "WinUAE": {
                "program": {
                    "windows": "WinUAE/windows/winuae64.exe",
                    "linux": "WinUAE/windows/winuae64.exe"
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
        if programs.ShouldProgramBeInstalled("WinUAE", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://www.winuae.net/download",
                webpage_base_url = "https://www.winuae.net",
                starts_with = "https://download.abime.net/winuae/releases/WinUAE",
                ends_with = "x64.zip",
                search_file = "winuae64.exe",
                install_name = "WinUAE",
                install_dir = programs.GetProgramInstallDir("WinUAE", "windows"),
                backups_dir = programs.GetProgramBackupDir("WinUAE", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup WinUAE")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("WinUAE", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("WinUAE", "windows"),
                install_name = "WinUAE",
                install_dir = programs.GetProgramInstallDir("WinUAE", "windows"),
                search_file = "winuae64.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup WinUAE")
