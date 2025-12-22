# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import release
import programs
import toolbase

# Config files
config_files = {}

# Sigtop tool
class Sigtop(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Sigtop"

    # Get config
    def get_config(self):
        return {
            "Sigtop": {
                "program": {
                    "windows": "Sigtop/windows/sigtop.exe",
                    "linux": "Sigtop/windows/sigtop.exe"
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
        if programs.should_program_be_installed("Sigtop", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "tbvdm",
                github_repo = "sigtop",
                starts_with = "sigtop",
                ends_with = ".exe",
                search_file = "sigtop.exe",
                install_name = "Sigtop",
                install_dir = programs.get_program_install_dir("Sigtop", "windows"),
                backups_dir = programs.get_program_backup_dir("Sigtop", "windows"),
                install_files = ["sigtop.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sigtop")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Sigtop", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Sigtop", "windows"),
                install_name = "Sigtop",
                install_dir = programs.get_program_install_dir("Sigtop", "windows"),
                search_file = "sigtop.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sigtop")
                return False
        return True
