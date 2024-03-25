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

# BSnes emulator
class BSnes(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BSnes"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "BSnes": {
                "program": {
                    "windows": "BSnes/windows/bsnes.exe",
                    "linux": "BSnes/windows/bsnes.exe"
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
        if programs.ShouldProgramBeInstalled("BSnes", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "bsnes-emu",
                github_repo = "bsnes",
                starts_with = "bsnes-windows",
                ends_with = ".zip",
                search_file = "bsnes.exe",
                install_name = "BSnes",
                install_dir = programs.GetProgramInstallDir("BSnes", "windows"),
                backups_dir = programs.GetProgramBackupDir("BSnes", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BSnes")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BSnes", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BSnes", "windows"),
                install_name = "BSnes",
                install_dir = programs.GetProgramInstallDir("BSnes", "windows"),
                search_file = "bsnes.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BSnes")
