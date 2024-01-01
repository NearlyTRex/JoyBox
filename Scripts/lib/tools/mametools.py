# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# MameTools tool
class MameTools(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "MameTools"

    # Get config
    def GetConfig(self):

        # MameChdman
        return {
            "MameChdman": {
                "program": {
                    "windows": "MameChdman/windows/chdman.exe",
                    "linux": "MameChdman/windows/chdman.exe"
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
        if programs.ShouldProgramBeInstalled("MameChdman", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "chdman.exe",
                install_name = "MameChdman",
                install_dir = programs.GetProgramInstallDir("MameChdman", "windows"),
                install_files = ["chdman.exe"],
                installer_type = config.installer_type_7zip,
                is_installer = False,
                is_archive = True,
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup MameChdman")
