# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):

        # MameChdman
        if force_downloads or programs.ShouldProgramBeInstalled("MameChdman", "windows"):
            network.DownloadLatestGithubRelease(
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
