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

# NDecrypt tool
class NDecrypt(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "NDecrypt"

    # Get config
    def get_config(self):
        return {
            "NDecrypt": {
                "program": {
                    "windows": "NDecrypt/windows/NDecrypt.exe",
                    "linux": "NDecrypt/linux/NDecrypt"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("NDecrypt", "windows"):
            success = release.download_github_release(
                github_user = "SabreTools",
                github_repo = "NDecrypt",
                starts_with = "NDecrypt",
                ends_with = "win-x64.zip",
                search_file = "NDecrypt.exe",
                install_name = "NDecrypt",
                install_dir = programs.get_program_install_dir("NDecrypt", "windows"),
                backups_dir = programs.get_program_backup_dir("NDecrypt", "windows"),
                install_files = ["NDecrypt.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NDecrypt")
                return False

        # Download linux program
        if programs.should_program_be_installed("NDecrypt", "linux"):
            success = release.download_github_release(
                github_user = "SabreTools",
                github_repo = "NDecrypt",
                starts_with = "NDecrypt",
                ends_with = "linux-x64.zip",
                search_file = "NDecrypt",
                install_name = "NDecrypt",
                install_dir = programs.get_program_install_dir("NDecrypt", "linux"),
                backups_dir = programs.get_program_backup_dir("NDecrypt", "linux"),
                install_files = ["NDecrypt"],
                chmod_files = [
                    {
                        "file": "NDecrypt",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NDecrypt")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("NDecrypt", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("NDecrypt", "windows"),
                install_name = "NDecrypt",
                install_dir = programs.get_program_install_dir("NDecrypt", "windows"),
                search_file = "NDecrypt.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NDecrypt")
                return False

        # Setup linux program
        if programs.should_program_be_installed("NDecrypt", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("NDecrypt", "linux"),
                install_name = "NDecrypt",
                install_dir = programs.get_program_install_dir("NDecrypt", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup NDecrypt")
                return False
        return True
