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

# A7800 emulator
class A7800(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "A7800"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "A7800": {
                "program": {
                    "windows": "A7800/windows/a7800.exe",
                    "linux": "A7800/windows/a7800.exe"
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
        if programs.ShouldProgramBeInstalled("A7800", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "7800-devtools",
                github_repo = "a7800",
                starts_with = "a7800-win",
                ends_with = ".zip",
                search_file = "a7800.exe",
                install_name = "A7800",
                install_dir = programs.GetProgramInstallDir("A7800", "windows"),
                backups_dir = programs.GetProgramBackupDir("A7800", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup A7800")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("A7800", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("A7800", "windows"),
                install_name = "A7800",
                install_dir = programs.GetProgramInstallDir("A7800", "windows"),
                search_file = "a7800.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup A7800")
