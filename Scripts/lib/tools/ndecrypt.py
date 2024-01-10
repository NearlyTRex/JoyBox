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

# NDecrypt tool
class NDecrypt(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "NDecrypt"

    # Get config
    def GetConfig(self):
        return {
            "NDecrypt": {
                "program": {
                    "windows": "NDecrypt/windows/NDecrypt.exe",
                    "linux": "NDecrypt/linux/NDecrypt"
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
        if programs.ShouldProgramBeInstalled("NDecrypt", "windows"):
            success = release.DownloadLatestGithubRelease(
                github_user = "SabreTools",
                github_repo = "NDecrypt",
                starts_with = "NDecrypt",
                ends_with = "win-x64.zip",
                search_file = "NDecrypt.exe",
                install_name = "NDecrypt",
                install_dir = programs.GetProgramInstallDir("NDecrypt", "windows"),
                install_files = ["NDecrypt.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup NDecrypt")

        # Download linux program
        if programs.ShouldProgramBeInstalled("NDecrypt", "linux"):
            success = release.DownloadLatestGithubRelease(
                github_user = "SabreTools",
                github_repo = "NDecrypt",
                starts_with = "NDecrypt",
                ends_with = "linux-x64.zip",
                search_file = "NDecrypt",
                install_name = "NDecrypt",
                install_dir = programs.GetProgramInstallDir("NDecrypt", "linux"),
                install_files = ["NDecrypt"],
                chmod_files = [
                    {
                        "file": "NDecrypt",
                        "perms": 755
                    }
                ],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup NDecrypt")
