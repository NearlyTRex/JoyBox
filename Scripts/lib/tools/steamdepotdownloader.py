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

# SteamDepotDownloader tool
class SteamDepotDownloader(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "SteamDepotDownloader"

    # Get config
    def get_config(self):
        return {
            "SteamDepotDownloader": {
                "program": {
                    "windows": "SteamDepotDownloader/windows/DepotDownloader.exe",
                    "linux": "SteamDepotDownloader/linux/DepotDownloader"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "SteamRE",
                github_repo = "DepotDownloader",
                starts_with = "DepotDownloader-windows-x64",
                ends_with = ".zip",
                search_file = "DepotDownloader.exe",
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "windows"),
                backups_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "windows"),
                install_files = ["DepotDownloader.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamDepotDownloader")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "SteamRE",
                github_repo = "DepotDownloader",
                starts_with = "DepotDownloader-linux-x64",
                ends_with = ".zip",
                search_file = "DepotDownloader",
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "linux"),
                backups_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "linux"),
                install_files = ["DepotDownloader"],
                chmod_files = [
                    {
                        "file": "DepotDownloader",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamDepotDownloader")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "windows"),
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "windows"),
                search_file = "DepotDownloader.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamDepotDownloader")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "linux"),
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamDepotDownloader")
                return False
        return True
