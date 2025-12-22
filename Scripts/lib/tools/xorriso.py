# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import release
import programs
import toolbase

# Config files
config_files = {}

# XorrISO tool
class XorrISO(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "XorrISO"

    # Get config
    def get_config(self):
        return {
            "XorrISO": {
                "program": {
                    "windows": "XorrISO/windows/xorriso.exe",
                    "linux": "XorrISO/linux/XorrISO.AppImage"
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
        if programs.should_program_be_installed("XorrISO", "windows"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.get_program_install_dir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "XorrISOWindows",
                output_dir = programs.get_program_backup_dir("XorrISO", "windows"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False

        # Build linux program
        if programs.should_program_be_installed("XorrISO", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://ftp.gnu.org/gnu/xorriso/xorriso-1.5.2.tar.gz",
                output_file = "App-x86_64.AppImage",
                install_name = "XorrISO",
                install_dir = programs.get_program_install_dir("XorrISO", "linux"),
                backups_dir = programs.get_program_backup_dir("XorrISO", "linux"),
                build_cmd = [
                    "cd", "xorriso-1.5.2",
                    "./bootstrap",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/xorriso-1.5.2/xorriso/xorriso", "to": "AppImage/usr/bin/xorriso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xorriso", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("XorrISO", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("XorrISO", "windows"),
                install_name = "XorrISO",
                install_dir = programs.get_program_install_dir("XorrISO", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False

        # Setup linux program
        if programs.should_program_be_installed("XorrISO", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("XorrISO", "linux"),
                install_name = "XorrISO",
                install_dir = programs.get_program_install_dir("XorrISO", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup XorrISO")
                return False
        return True
