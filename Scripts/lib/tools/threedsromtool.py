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

# ThreeDSRomTool tool
class ThreeDSRomTool(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "3DSRomTool"

    # Get config
    def get_config(self):
        return {
            "3DSRomTool": {
                "program": {
                    "windows": "3DSRomTool/windows/rom_tool.exe",
                    "linux": "3DSRomTool/linux/3DSRomTool.AppImage"
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
        if programs.should_program_be_installed("3DSRomTool", "windows"):
            success = release.download_github_release(
                github_user = "NearlyTRex",
                github_repo = "3DSRomTool",
                starts_with = "rom_tool",
                ends_with = ".zip",
                search_file = "rom_tool.exe",
                install_name = "3DSRomTool",
                install_dir = programs.get_program_install_dir("3DSRomTool", "windows"),
                backups_dir = programs.get_program_backup_dir("3DSRomTool", "windows"),
                install_files = ["rom_tool.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup 3DSRomTool")
                return False

        # Build linux program
        if programs.should_program_be_installed("3DSRomTool", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/3DSRomTool.git",
                output_file = "App-x86_64.AppImage",
                install_name = "3DSRomTool",
                install_dir = programs.get_program_install_dir("3DSRomTool", "linux"),
                backups_dir = programs.get_program_backup_dir("3DSRomTool", "linux"),
                build_cmd = [
                    "cd", "rom_tool",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/rom_tool/rom_tool", "to": "AppImage/usr/bin/rom_tool"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/rom_tool", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup 3DSRomTool")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("3DSRomTool", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("3DSRomTool", "windows"),
                install_name = "3DSRomTool",
                install_dir = programs.get_program_install_dir("3DSRomTool", "windows"),
                search_file = "rom_tool.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup 3DSRomTool")
                return False

        # Setup linux program
        if programs.should_program_be_installed("3DSRomTool", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("3DSRomTool", "linux"),
                install_name = "3DSRomTool",
                install_dir = programs.get_program_install_dir("3DSRomTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup 3DSRomTool")
                return False
        return True
