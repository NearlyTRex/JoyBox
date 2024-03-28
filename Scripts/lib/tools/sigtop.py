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

# Sigtop tool
class Sigtop(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Sigtop"

    # Get config
    def GetConfig(self):
        return {
            "Sigtop": {
                "program": {
                    "windows": "Sigtop/windows/sigtop.exe",
                    "linux": "Sigtop/windows/sigtop.exe"
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
        if programs.ShouldProgramBeInstalled("Sigtop", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "tbvdm",
                github_repo = "sigtop",
                starts_with = "sigtop",
                ends_with = ".exe",
                search_file = "sigtop.exe",
                install_name = "Sigtop",
                install_dir = programs.GetProgramInstallDir("Sigtop", "windows"),
                backups_dir = programs.GetProgramBackupDir("Sigtop", "windows"),
                install_files = ["sigtop.exe"],
                release_type = config.release_type_program,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sigtop")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Sigtop", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Sigtop", "windows"),
                install_name = "Sigtop",
                install_dir = programs.GetProgramInstallDir("Sigtop", "windows"),
                search_file = "sigtop.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sigtop")
