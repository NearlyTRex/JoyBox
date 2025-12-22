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

# Stella emulator
class Stella(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Stella"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Stella": {
                "program": {
                    "windows": "Stella/windows/Stella.exe",
                    "linux": "Stella/windows/Stella.exe"
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
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "stella-emu",
                github_repo = "stella",
                starts_with = "Stella",
                ends_with = "windows.zip",
                search_file = "64-bit/Stella.exe",
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                backups_dir = programs.get_program_backup_dir("Stella", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Stella", "windows"),
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                search_file = "64-bit/Stella.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True
