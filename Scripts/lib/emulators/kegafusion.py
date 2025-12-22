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

# KegaFusion emulator
class KegaFusion(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "KegaFusion"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "KegaFusion": {
                "program": {
                    "windows": "KegaFusion/windows/Fusion.exe",
                    "linux": "KegaFusion/windows/Fusion.exe"
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
        if programs.should_program_be_installed("KegaFusion", "windows"):
            success = release.download_general_release(
                archive_url = "https://retrocdn.net/images/6/6c/Fusion364.7z",
                search_file = "Fusion.exe",
                install_name = "KegaFusion",
                install_dir = programs.get_program_install_dir("KegaFusion", "windows"),
                backups_dir = programs.get_program_backup_dir("KegaFusion", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup KegaFusion")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("KegaFusion", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("KegaFusion", "windows"),
                install_name = "KegaFusion",
                install_dir = programs.get_program_install_dir("KegaFusion", "windows"),
                search_file = "Fusion.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup KegaFusion")
                return False
        return True
