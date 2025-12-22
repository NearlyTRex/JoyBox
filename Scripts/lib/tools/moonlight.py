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
config_files["Moonlight/linux/Moonlight.AppImage.home/.config/Moonlight Game Streaming Project/Moonlight.conf"] = ""

# Moonlight tool
class Moonlight(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Moonlight"

    # Get config
    def GetConfig(self):
        return {
            "Moonlight": {
                "program": {
                    "windows": "Moonlight/windows/Moonlight.exe",
                    "linux": "Moonlight/linux/Moonlight.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("Moonlight", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "moonlight-stream",
                github_repo = "moonlight-qt",
                starts_with = "MoonlightPortable-x64",
                ends_with = ".zip",
                search_file = "Moonlight.exe",
                install_name = "Moonlight",
                install_dir = programs.GetProgramInstallDir("Moonlight", "windows"),
                backups_dir = programs.GetProgramBackupDir("Moonlight", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Moonlight")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("Moonlight", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "moonlight-stream",
                github_repo = "moonlight-qt",
                starts_with = "Moonlight",
                ends_with = "x86_64.AppImage",
                install_name = "Moonlight",
                install_dir = programs.GetProgramInstallDir("Moonlight", "linux"),
                backups_dir = programs.GetProgramBackupDir("Moonlight", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Moonlight")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Moonlight", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Moonlight", "windows"),
                install_name = "Moonlight",
                install_dir = programs.GetProgramInstallDir("Moonlight", "windows"),
                search_file = "Moonlight.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Moonlight")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Moonlight", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Moonlight", "linux"),
                install_name = "Moonlight",
                install_dir = programs.GetProgramInstallDir("Moonlight", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Moonlight")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
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
                logger.log_error("Could not setup Moonlight config files")
                return False
        return True
