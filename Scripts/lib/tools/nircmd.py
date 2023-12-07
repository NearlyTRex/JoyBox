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

# NirCmd tool
class NirCmd(base.ToolBase):

    # Get name
    def GetName():
        return "NirCmd"

    # Get config
    def GetConfig():
        return {
            "NirCmd": {
                "program": {
                    "windows": "NirCmd/windows/nircmdc.exe",
                    "linux": "NirCmd/windows/nircmdc.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("NirCmd", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://www.nirsoft.net/utils/nircmd-x64.zip",
                search_file = "nircmdc.exe",
                install_name = "NirCmd",
                install_dir = programs.GetProgramInstallDir("NirCmd", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)