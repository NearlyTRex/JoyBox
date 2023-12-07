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

# Pegasus tool
class Pegasus(base.ToolBase):

    # Get name
    def GetName():
        return "Pegasus"

    # Get config
    def GetConfig():
        return {
            "Pegasus": {
                "program": {
                    "windows": "Pegasus/windows/pegasus-fe.exe",
                    "linux": "Pegasus/linux/pegasus-fe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Pegasus", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mmatyas",
                github_repo = "pegasus-frontend",
                starts_with = "pegasus-fe",
                ends_with = "win-mingw-static.zip",
                search_file = "pegasus-fe.exe",
                install_name = "Pegasus",
                install_dir = programs.GetProgramInstallDir("Pegasus", "windows"),
                install_files = ["pegasus-fe.exe"],
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Pegasus", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mmatyas",
                github_repo = "pegasus-frontend",
                starts_with = "pegasus-fe",
                ends_with = "x11-static.zip",
                search_file = "pegasus-fe",
                install_name = "Pegasus",
                install_dir = programs.GetProgramInstallDir("Pegasus", "linux"),
                install_files = ["pegasus-fe"],
                chmod_files = [
                    {
                        "file": "pegasus-fe",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
