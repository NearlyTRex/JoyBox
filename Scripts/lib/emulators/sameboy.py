# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import logger
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# SameBoy emulator
class SameBoy(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "SameBoy"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "SameBoy": {
                "program": {
                    "windows": "SameBoy/windows/sameboy.exe",
                    "linux": "SameBoy/windows/sameboy.exe"
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
        if programs.ShouldProgramBeInstalled("SameBoy", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "LIJI32",
                github_repo = "SameBoy",
                starts_with = "sameboy_winsdl",
                ends_with = ".zip",
                search_file = "sameboy.exe",
                install_name = "SameBoy",
                install_dir = programs.GetProgramInstallDir("SameBoy", "windows"),
                backups_dir = programs.GetProgramBackupDir("SameBoy", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("SameBoy", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SameBoy", "windows"),
                install_name = "SameBoy",
                install_dir = programs.GetProgramInstallDir("SameBoy", "windows"),
                search_file = "sameboy.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True
