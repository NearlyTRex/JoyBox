# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import release
import programs
import environment
import fileops
import toolbase

# Config files
config_files = {}
config_files["AppImageTool/linux/app.desktop"] = """
[Desktop Entry]
Type=Application
Name=App
Icon=icon
Categories=Game;
"""

# AppImageTool tool
class AppImageTool(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "AppImageTool"

    # Get config
    def get_config(self):
        return {
            "AppImageTool": {
                "program": {
                    "windows": None,
                    "linux": "AppImageTool/linux/AppImageTool.AppImage"
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

        # Download linux program
        if programs.should_program_be_installed("AppImageTool", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "AppImage",
                github_repo = "AppImageKit",
                starts_with = "appimagetool-x86_64",
                ends_with = ".AppImage",
                search_file = "AppImageTool.AppImage",
                install_name = "AppImageTool",
                install_dir = programs.get_program_install_dir("AppImageTool", "linux"),
                backups_dir = programs.get_program_backup_dir("AppImageTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup linux program
        if programs.should_program_be_installed("AppImageTool", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("AppImageTool", "linux"),
                install_name = "AppImageTool",
                install_dir = programs.get_program_install_dir("AppImageTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Copy icon
        if environment.is_linux_platform():
            success = fileops.copy_file_or_directory(
                src = paths.join_paths(environment.get_scripts_icons_dir(), "BostonIcons", "128", "mimes", "application-x-executable-script.svg"),
                dest = paths.join_paths(programs.get_program_install_dir("AppImageTool", "linux"), "icon.svg"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not copy AppImageTool icons")
                return False

        # Create config files
        if environment.is_linux_platform():
            for config_filename, config_contents in config_files.items():
                success = fileops.touch_file(
                    src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not create AppImageTool config files")
                    return False
        return True
