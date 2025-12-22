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

# Demul emulator
class Demul(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Demul"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Demul": {
                "program": {
                    "windows": "Demul/windows/demul.exe",
                    "linux": "Demul/windows/demul.exe"
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
        if programs.should_program_be_installed("Demul", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "http://demul.emulation64.com/downloads/",
                webpage_base_url = "http://demul.emulation64.com",
                starts_with = "http://demul.emulation64.com/files/demul",
                ends_with = ".7z",
                search_file = "demul.exe",
                install_name = "Demul",
                install_dir = programs.get_program_install_dir("Demul", "windows"),
                backups_dir = programs.get_program_backup_dir("Demul", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Demul")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Demul", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Demul", "windows"),
                install_name = "Demul",
                install_dir = programs.get_program_install_dir("Demul", "windows"),
                search_file = "demul.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Demul")
                return False
        return True
