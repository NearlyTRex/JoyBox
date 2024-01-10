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

# GeckoDriver tool
class GeckoDriver(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "GeckoDriver"

    # Get config
    def GetConfig(self):
        return {
            "GeckoDriver": {
                "program": {
                    "windows": "GeckoDriver/windows/geckodriver.exe",
                    "linux": "GeckoDriver/linux/geckodriver"
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
        if programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            success = release.DownloadLatestGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "win32.zip",
                search_file = "geckodriver.exe",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                install_files = ["geckodriver.exe"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")

        # Download linux program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            success = release.DownloadLatestGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "linux64.tar.gz",
                search_file = "geckodriver",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                install_files = ["geckodriver"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")
