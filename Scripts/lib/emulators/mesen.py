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

# Mesen emulator
class Mesen(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Mesen"

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {
            "Mesen": {
                "program": {
                    "windows": "Mesen/windows/Mesen.exe",
                    "linux": "Mesen/linux/Mesen.AppImage"
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
        if programs.should_program_be_installed("Mesen", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://nightly.link/SourMesen/Mesen2/workflows/build/master/Mesen%20%28Windows%20-%20net8.0%29.zip",
                search_file = "Mesen.exe",
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "windows"),
                backups_dir = programs.get_program_backup_dir("Mesen", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False

        # Download linux program
        if programs.should_program_be_installed("Mesen", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://nightly.link/SourMesen/Mesen2/workflows/build/master/Mesen%20(Linux%20x64%20-%20AppImage).zip",
                search_file = "Mesen.AppImage",
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "linux"),
                backups_dir = programs.get_program_backup_dir("Mesen", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Mesen", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Mesen", "windows"),
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "windows"),
                search_file = "Mesen.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Mesen", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Mesen", "linux"),
                install_name = "Mesen",
                install_dir = programs.get_program_install_dir("Mesen", "linux"),
                search_file = "Mesen.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mesen")
                return False
        return True
