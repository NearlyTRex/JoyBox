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

# Steamless tool
class Steamless(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Steamless"

    # Get config
    def GetConfig(self):
        return {
            "Steamless": {
                "program": {
                    "windows": "Steamless/windows/Steamless.CLI.exe",
                    "linux": "Steamless/windows/Steamless.CLI.exe"
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
        if programs.ShouldProgramBeInstalled("Steamless", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "atom0s",
                github_repo = "Steamless",
                starts_with = "Steamless",
                ends_with = ".zip",
                search_file = "Steamless.CLI.exe",
                install_name = "Steamless",
                install_dir = programs.GetProgramInstallDir("Steamless", "windows"),
                backups_dir = programs.GetProgramBackupDir("Steamless", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Steamless")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Steamless", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Steamless", "windows"),
                install_name = "Steamless",
                install_dir = programs.GetProgramInstallDir("Steamless", "windows"),
                search_file = "Steamless.CLI.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Steamless")
