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

# PS3Dec tool
class PS3Dec(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "PS3Dec"

    # Get config
    def get_config(self):
        return {
            "PS3Dec": {
                "program": {
                    "windows": "PS3Dec/windows/PS3Dec.exe",
                    "linux": "PS3Dec/linux/PS3Dec.AppImage"
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
        if programs.should_program_be_installed("PS3Dec", "windows"):
            success = release.download_github_release(
                github_user = "NearlyTRex",
                github_repo = "PS3Dec",
                starts_with = "PS3Dec",
                ends_with = ".zip",
                search_file = "PS3Dec.exe",
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "windows"),
                backups_dir = programs.get_program_backup_dir("PS3Dec", "windows"),
                install_files = ["PS3Dec.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False

        # Build linux program
        if programs.should_program_be_installed("PS3Dec", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/PS3Dec.git",
                output_file = "App-x86_64.AppImage",
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "linux"),
                backups_dir = programs.get_program_backup_dir("PS3Dec", "linux"),
                build_cmd = [
                    "cmake", "-G", "Ninja", "..",
                    "&&",
                    "ninja"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Release/PS3Dec", "to": "AppImage/usr/bin/PS3Dec"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PS3Dec", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("PS3Dec", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PS3Dec", "windows"),
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "windows"),
                search_file = "PS3Dec.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False

        # Setup linux program
        if programs.should_program_be_installed("PS3Dec", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PS3Dec", "linux"),
                install_name = "PS3Dec",
                install_dir = programs.get_program_install_dir("PS3Dec", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PS3Dec")
                return False
        return True
