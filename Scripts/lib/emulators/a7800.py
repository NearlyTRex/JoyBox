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

# A7800 emulator
class A7800(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "A7800"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup A7800")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("A7800", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("A7800", "windows"),
                install_name = "A7800",
                install_dir = programs.GetProgramInstallDir("A7800", "windows"),
                search_file = "a7800.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup A7800")
                return False
        return True
