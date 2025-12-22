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

# BSnes emulator
class BSnes(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "BSnes"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BSnes")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BSnes", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BSnes", "windows"),
                install_name = "BSnes",
                install_dir = programs.GetProgramInstallDir("BSnes", "windows"),
                search_file = "bsnes.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BSnes")
                return False
        return True
