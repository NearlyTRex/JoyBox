# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

# SteamDepotDownloader tool
class SteamDepotDownloader(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "SteamDepotDownloader"

    # Get config
    def GetConfig(self):
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
    def Setup(self, verbose = False, exit_on_failure = False):

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
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SteamDepotDownloader")

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
                release_type = config.release_type_archive,
                chmod_files = [
                    {
                        "file": "DepotDownloader",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SteamDepotDownloader")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "windows"),
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "windows"),
                search_file = "DepotDownloader.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SteamDepotDownloader")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("SteamDepotDownloader", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("SteamDepotDownloader", "linux"),
                install_name = "SteamDepotDownloader",
                install_dir = programs.GetProgramInstallDir("SteamDepotDownloader", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup SteamDepotDownloader")
