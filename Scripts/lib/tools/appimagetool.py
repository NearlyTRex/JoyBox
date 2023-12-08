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

# AppImageTool tool
class AppImageTool(base.ToolBase):

    # Get name
    def GetName(self):
        return "AppImageTool"

    # Get config
    def GetConfig(self):
        return {
            "AppImageTool": {
                "program": {
                    "windows": None,
                    "linux": "AppImageTool/linux/AppImageTool.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("AppImageTool", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "AppImage",
                github_repo = "AppImageKit",
                starts_with = "appimagetool-x86_64",
                ends_with = ".AppImage",
                search_file = "AppImageTool.AppImage",
                install_name = "AppImageTool",
                install_dir = programs.GetProgramInstallDir("AppImageTool", "linux"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
