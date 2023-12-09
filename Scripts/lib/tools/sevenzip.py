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

# SevenZip tool
class SevenZip(base.ToolBase):

    # Get name
    def GetName(self):
        return "7-Zip"

    # Get config
    def GetConfig(self):
        return {

            # "7-Zip"
            "7-Zip": {
                "program": {
                    "windows": "7-Zip/windows/7z.exe",
                    "linux": "7-Zip/windows/7z.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            },

            # 7-Zip-Standalone
            "7-Zip-Standalone": {
                "program": {
                    "windows": "7-Zip/windows/7za.exe",
                    "linux": "7-Zip/windows/7za.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):

        # 7-Zip
        if force_downloads or programs.ShouldProgramBeInstalled("7-Zip", "windows"):
            network.DownloadLatestWebpageRelease(
                webpage_url = "https://www.7-zip.org/download.html",
                starts_with = "https://www.7-zip.org/a/7z",
                ends_with = "-x64.exe",
                search_file = "7z.exe",
                install_name = "7-Zip",
                install_dir = programs.GetProgramInstallDir("7-Zip", "windows"),
                installer_type = config.installer_format_nsis,
                is_installer = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # 7-Zip-Standalone
        if force_downloads or programs.ShouldProgramBeInstalled("7-Zip-Standalone", "windows"):
            network.DownloadLatestWebpageRelease(
                webpage_url = "https://www.7-zip.org/download.html",
                starts_with = "https://www.7-zip.org/a/7z",
                ends_with = "-extra.7z",
                search_file = "x64/7za.exe",
                install_name = "7-Zip",
                install_dir = programs.GetProgramInstallDir("7-Zip", "windows"),
                install_files = ["7za.dll", "7za.exe", "7zxa.dll"],
                verbose = verbose,
                exit_on_failure = exit_on_failure)
