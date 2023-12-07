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

# NDecrypt tool
class NDecrypt(base.ToolBase):

    # Get name
    def GetName():
        return "NDecrypt"

    # Get config
    def GetConfig():
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

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("NDecrypt", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "SabreTools",
                github_repo = "NDecrypt",
                starts_with = "NDecrypt",
                ends_with = "win-x64.zip",
                search_file = "NDecrypt.exe",
                install_name = "NDecrypt",
                install_dir = programs.GetProgramInstallDir("NDecrypt", "windows"),
                install_files = ["NDecrypt.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("NDecrypt", "linux"):
            network.DownloadLatestGithubRelease(
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
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
