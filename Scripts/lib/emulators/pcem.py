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

# PCEm emulator
class PCEm(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "PCEm"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "PCEm": {
                "program": {
                    "windows": "PCEm/windows/PCem.exe",
                    "linux": "PCEm/windows/PCem.exe"
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
        if programs.ShouldProgramBeInstalled("PCEm", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "sarah-walker-pcem",
                github_repo = "pcem",
                starts_with = "PCem",
                ends_with = "Win.zip",
                search_file = "PCem.exe",
                install_name = "PCEm",
                install_dir = programs.GetProgramInstallDir("PCEm", "windows"),
                backups_dir = programs.GetProgramBackupDir("PCEm", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup PCEm")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("PCEm", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PCEm", "windows"),
                install_name = "PCEm",
                install_dir = programs.GetProgramInstallDir("PCEm", "windows"),
                search_file = "PCem.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup PCEm")
                return False
        return True
