# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import environment
import release
import programs
import toolbase

# Config files
config_files = {}

# BalenaEtcher tool
class BalenaEtcher(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "BalenaEtcher"

    # Get config
    def get_config(self):
        return {
            "BalenaEtcher": {
                "program": {
                    "windows": "BalenaEtcher/windows/balenaEtcher.exe",
                    "linux": "BalenaEtcher/linux/BalenaEtcher.AppImage"
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
        if programs.should_program_be_installed("BalenaEtcher", "windows"):
            success = release.download_github_release(
                github_user = "balena-io",
                github_repo = "etcher",
                starts_with = "balenaEtcher-win32-x64",
                ends_with = ".zip",
                search_file = "balenaEtcher.exe",
                install_name = "BalenaEtcher",
                install_dir = programs.get_program_install_dir("BalenaEtcher", "windows"),
                backups_dir = programs.get_program_backup_dir("BalenaEtcher", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BalenaEtcher")
                return False

        # Download linux program
        if programs.should_program_be_installed("BalenaEtcher", "linux"):
            success = release.download_github_release(
                github_user = "balena-io",
                github_repo = "etcher",
                starts_with = "balenaEtcher",
                ends_with = ".AppImage",
                install_name = "BalenaEtcher",
                install_dir = programs.get_program_install_dir("BalenaEtcher", "linux"),
                backups_dir = programs.get_program_backup_dir("BalenaEtcher", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BalenaEtcher")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BalenaEtcher", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BalenaEtcher", "windows"),
                install_name = "BalenaEtcher",
                install_dir = programs.get_program_install_dir("BalenaEtcher", "windows"),
                search_file = "balenaEtcher.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BalenaEtcher")
                return False

        # Setup linux program
        if programs.should_program_be_installed("BalenaEtcher", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BalenaEtcher", "linux"),
                install_name = "BalenaEtcher",
                install_dir = programs.get_program_install_dir("BalenaEtcher", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BalenaEtcher")
                return False
        return True
