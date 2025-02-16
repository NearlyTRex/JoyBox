# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import release
import programs
import toolbase

# Config files
config_files = {}

# YtDlp tool
class YtDlp(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "YtDlp"

    # Get config
    def GetConfig(self):
        return {
            "YtDlp": {
                "program": {
                    "windows": "YtDlp/windows/yt-dlp.exe",
                    "linux": "YtDlp/linux/yt-dlp_linux"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("YtDlp", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "yt-dlp",
                github_repo = "yt-dlp",
                starts_with = "yt-dlp",
                ends_with = ".exe",
                search_file = "yt-dlp.exe",
                install_name = "YtDlp",
                install_dir = programs.GetProgramInstallDir("YtDlp", "windows"),
                backups_dir = programs.GetProgramBackupDir("YtDlp", "windows"),
                install_files = ["yt-dlp.exe"],
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup YtDlp")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("YtDlp", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "yt-dlp",
                github_repo = "yt-dlp",
                starts_with = "yt-dlp",
                ends_with = "_linux",
                search_file = "yt-dlp_linux",
                install_name = "YtDlp",
                install_dir = programs.GetProgramInstallDir("YtDlp", "linux"),
                backups_dir = programs.GetProgramBackupDir("YtDlp", "linux"),
                install_files = ["yt-dlp_linux"],
                release_type = config.ReleaseType.PROGRAM,
                chmod_files = [
                    {
                        "file": "yt-dlp_linux",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup YtDlp")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("YtDlp", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("YtDlp", "windows"),
                install_name = "YtDlp",
                install_dir = programs.GetProgramInstallDir("YtDlp", "windows"),
                search_file = "yt-dlp.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup YtDlp")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("YtDlp", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("YtDlp", "linux"),
                install_name = "YtDlp",
                install_dir = programs.GetProgramInstallDir("YtDlp", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup YtDlp")
                return False
        return True
