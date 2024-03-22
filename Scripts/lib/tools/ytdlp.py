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
    def Setup(self, verbose = False, exit_on_failure = False):

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
                install_files = ["yt-dlp.exe"],
                release_type = config.release_type_program,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup YtDlp")

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
                install_files = ["yt-dlp_linux"],
                release_type = config.release_type_program,
                chmod_files = [
                    {
                        "file": "yt-dlp_linux",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup YtDlp")
