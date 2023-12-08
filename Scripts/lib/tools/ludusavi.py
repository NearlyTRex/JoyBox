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

# Ludusavi tool
class Ludusavi(base.ToolBase):

    # Get name
    def GetName(self):
        return "Ludusavi"

    # Get config
    def GetConfig(self):
        return {
            "Ludusavi": {
                "program": {
                    "windows": "Ludusavi/windows/ludusavi.exe",
                    "linux": "Ludusavi/linux/ludusavi"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Ludusavi", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "win64.zip",
                search_file = "ludusavi.exe",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "windows"),
                install_files = ["ludusavi.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Ludusavi", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mtkennerly",
                github_repo = "ludusavi",
                starts_with = "ludusavi",
                ends_with = "linux.zip",
                search_file = "ludusavi",
                install_name = "Ludusavi",
                install_dir = programs.GetProgramInstallDir("Ludusavi", "linux"),
                install_files = ["ludusavi"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
