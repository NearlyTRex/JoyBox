# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# Sunshine tool
class Sunshine(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Sunshine"

    # Get config
    def GetConfig(self):
        return {
            "Sunshine": {
                "program": {
                    "windows": "Sunshine/windows/sunshine.exe",
                    "linux": "Sunshine/linux/Sunshine.AppImage"
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
        if programs.ShouldProgramBeInstalled("Sunshine", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = "windows.zip",
                search_file = "sunshine.exe",
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "windows"),
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Sunshine", "linux"):
            success = network.DownloadLatestGithubRelease(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = ".AppImage",
                search_file = "Sunshine.AppImage",
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")
