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
    def get_name(self):
        return "SameBoy"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("SameBoy", "windows"):
            success = release.download_github_release(
                github_user = "LIJI32",
                github_repo = "SameBoy",
                starts_with = "sameboy_winsdl",
                ends_with = ".zip",
                search_file = "sameboy.exe",
                install_name = "SameBoy",
                install_dir = programs.get_program_install_dir("SameBoy", "windows"),
                backups_dir = programs.get_program_backup_dir("SameBoy", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("SameBoy", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("SameBoy", "windows"),
                install_name = "SameBoy",
                install_dir = programs.get_program_install_dir("SameBoy", "windows"),
                search_file = "sameboy.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True
