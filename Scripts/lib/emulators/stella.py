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

# Stella emulator
class Stella(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Stella"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Stella": {
                "program": {
                    "windows": "Stella/windows/Stella.exe",
                    "linux": "Stella/windows/Stella.exe"
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
        if programs.ShouldProgramBeInstalled("Stella", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "stella-emu",
                github_repo = "stella",
                starts_with = "Stella",
                ends_with = "windows.zip",
                search_file = "64-bit/Stella.exe",
                install_name = "Stella",
                install_dir = programs.GetProgramInstallDir("Stella", "windows"),
                backups_dir = programs.GetProgramBackupDir("Stella", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Stella")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Stella", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Stella", "windows"),
                install_name = "Stella",
                install_dir = programs.GetProgramInstallDir("Stella", "windows"),
                search_file = "64-bit/Stella.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Stella")
                return False
        return True
