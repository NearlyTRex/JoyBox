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

# CxBxReloaded emulator
class CxBxReloaded(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "CxBxReloaded"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "CxBxReloaded": {
                "program": {
                    "windows": "CxBxReloaded/windows/cxbx.exe",
                    "linux": "CxBxReloaded/windows/cxbx.exe"
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
        if programs.ShouldProgramBeInstalled("CxBxReloaded", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Cxbx-Reloaded",
                github_repo = "Cxbx-Reloaded",
                starts_with = "CxbxReloaded-Release-VS2022",
                ends_with = ".zip",
                search_file = "cxbx.exe",
                install_name = "CxBxReloaded",
                install_dir = programs.GetProgramInstallDir("CxBxReloaded", "windows"),
                backups_dir = programs.GetProgramBackupDir("CxBxReloaded", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CxBxReloaded")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("CxBxReloaded", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("CxBxReloaded", "windows"),
                install_name = "CxBxReloaded",
                install_dir = programs.GetProgramInstallDir("CxBxReloaded", "windows"),
                search_file = "cxbx.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup CxBxReloaded")
