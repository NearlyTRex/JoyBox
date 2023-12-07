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

# XCICutter tool
class XCICutter(base.ToolBase):

    # Get name
    def GetName():
        return "XCICutter"

    # Get config
    def GetConfig():
        return {
            "XCICutter": {
                "program": {
                    "windows": "XCICutter/windows/XCI-Cutter.exe",
                    "linux": "XCICutter/windows/XCI-Cutter.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("XCICutter", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "Destiny1984",
                github_repo = "XCI-Cutter",
                starts_with = "XCI-Cutter",
                ends_with = ".exe",
                search_file = "XCI-Cutter.exe",
                install_name = "XCICutter",
                install_dir = programs.GetProgramInstallDir("XCICutter", "windows"),
                install_files = ["XCI-Cutter.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)