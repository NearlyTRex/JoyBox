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

# ExtractXIso tool
class ExtractXIso(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "ExtractXIso"

    # Get config
    def get_config(self):
        return {
            "ExtractXIso": {
                "program": {
                    "windows": "ExtractXIso/windows/extract-xiso.exe",
                    "linux": "ExtractXIso/linux/ExtractXIso.AppImage"
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
        if programs.should_program_be_installed("ExtractXIso", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "XboxDev",
                github_repo = "extract-xiso",
                starts_with = "extract-xiso",
                ends_with = "win32-release.zip",
                search_file = "extract-xiso.exe",
                install_name = "ExtractXIso",
                install_dir = programs.get_program_install_dir("ExtractXIso", "windows"),
                backups_dir = programs.get_program_backup_dir("ExtractXIso", "windows"),
                install_files = ["extract-xiso.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExtractXIso")
                return False

        # Build linux program
        if programs.should_program_be_installed("ExtractXIso", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/ExtractXIso.git",
                output_file = "App-x86_64.AppImage",
                install_name = "ExtractXIso",
                install_dir = programs.get_program_install_dir("ExtractXIso", "linux"),
                backups_dir = programs.get_program_backup_dir("ExtractXIso", "linux"),
                build_cmd = [
                    "cmake", "..",
                    "&&",
                    "make"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/extract-xiso", "to": "AppImage/usr/bin/extract-xiso"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/extract-xiso", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExtractXIso")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("ExtractXIso", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("ExtractXIso", "windows"),
                install_name = "ExtractXIso",
                install_dir = programs.get_program_install_dir("ExtractXIso", "windows"),
                search_file = "extract-xiso.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExtractXIso")
                return False

        # Setup linux program
        if programs.should_program_be_installed("ExtractXIso", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("ExtractXIso", "linux"),
                install_name = "ExtractXIso",
                install_dir = programs.get_program_install_dir("ExtractXIso", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExtractXIso")
                return False
        return True
