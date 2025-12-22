# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import release
import programs
import toolbase

# Config files
config_files = {}
config_files["Sunshine/windows/config/sunshine.conf"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine.conf"] = ""

# Sunshine tool
class Sunshine(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Sunshine"

    # Get config
    def get_config(self):
        return {
            "Sunshine": {
                "program": {
                    "windows": "Sunshine/windows/sunshine.exe",
                    "linux": "Sunshine/linux/Sunshine.AppImage"
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
        if programs.should_program_be_installed("Sunshine", "windows"):
            success = release.download_github_release(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = "windows.zip",
                search_file = "sunshine.exe",
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "windows"),
                backups_dir = programs.get_program_backup_dir("Sunshine", "windows"),
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False

        # Download linux program
        if programs.should_program_be_installed("Sunshine", "linux"):
            success = release.download_github_release(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = ".AppImage",
                search_file = "Sunshine.AppImage",
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "linux"),
                backups_dir = programs.get_program_backup_dir("Sunshine", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Sunshine", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Sunshine", "windows"),
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "windows"),
                search_file = "sunshine.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Sunshine", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Sunshine", "linux"),
                install_name = "Sunshine",
                install_dir = programs.get_program_install_dir("Sunshine", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Sunshine config files")
                return False
        return True
