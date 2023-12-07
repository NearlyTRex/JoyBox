# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import network
import programs

# Local imports
from . import base

# MameTools tool
class MameTools(base.ToolBase):

    # Get name
    def GetName():
        return "MameTools"

    # Get config
    def GetConfig():

        # MameToolsChdman
        return {
            "MameToolsChdman": {
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
    def Download(force_downloads = False):

        # MameToolsChdman
        if force_downloads or programs.ShouldProgramBeInstalled("MameToolsChdman", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "chdman.exe",
                install_name = "MameToolsChdman",
                install_dir = programs.GetProgramInstallDir("MameTools", "windows"),
                install_files = ["chdman.exe"],
                installer_type = config.installer_format_7zip,
                is_installer = False,
                is_archive = True,
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
