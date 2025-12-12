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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Steamless")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Steamless", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Steamless", "windows"),
                install_name = "Steamless",
                install_dir = programs.GetProgramInstallDir("Steamless", "windows"),
                search_file = "Steamless.CLI.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Steamless")
                return False
        return True
