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

# CDecrypt tool
class CDecrypt(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "CDecrypt"

    # Get config
    def get_config(self):
        return {
            "CDecrypt": {
                "program": {
                    "windows": "CDecrypt/windows/cdecrypt.exe",
                    "linux": "CDecrypt/linux/CDecrypt.AppImage"
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
        if programs.should_program_be_installed("CDecrypt", "windows"):
            success = release.download_github_release(
                github_user = "VitaSmith",
                github_repo = "cdecrypt",
                starts_with = "cdecrypt",
                ends_with = ".zip",
                search_file = "cdecrypt.exe",
                install_name = "CDecrypt",
                install_dir = programs.get_program_install_dir("CDecrypt", "windows"),
                backups_dir = programs.get_program_backup_dir("CDecrypt", "windows"),
                install_files = ["cdecrypt.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CDecrypt")
                return False

        # Build linux program
        if programs.should_program_be_installed("CDecrypt", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/CDecrypt.git",
                output_file = "App-x86_64.AppImage",
                install_name = "CDecrypt",
                install_dir = programs.get_program_install_dir("CDecrypt", "linux"),
                backups_dir = programs.get_program_backup_dir("CDecrypt", "linux"),
                build_cmd = [
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/cdecrypt", "to": "AppImage/usr/bin/cdecrypt"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/cdecrypt", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CDecrypt")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("CDecrypt", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CDecrypt", "windows"),
                install_name = "CDecrypt",
                install_dir = programs.get_program_install_dir("CDecrypt", "windows"),
                search_file = "cdecrypt.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CDecrypt")
                return False

        # Setup linux program
        if programs.should_program_be_installed("CDecrypt", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CDecrypt", "linux"),
                install_name = "CDecrypt",
                install_dir = programs.get_program_install_dir("CDecrypt", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CDecrypt")
                return False
        return True
