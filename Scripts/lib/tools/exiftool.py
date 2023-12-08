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

# ExifTool tool
class ExifTool(base.ToolBase):

    # Get name
    def GetName(self):
        return "ExifTool"

    # Get config
    def GetConfig(self):
        return {
            "ExifTool": {
                "program": {
                    "windows": "ExifTool/windows/exiftool.exe",
                    "linux": "ExifTool/linux/exiftool"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("ExifTool", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://exiftool.org/exiftool-12.70.zip",
                search_file = "exiftool(-k).exe",
                install_name = "ExifTool",
                install_dir = programs.GetProgramInstallDir("ExifTool", "windows"),
                rename_files = [
                    {
                        "from": "exiftool(-k).exe",
                        "to": "exiftool.exe"
                    }
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("ExifTool", "linux"):
            network.DownloadGeneralRelease(
                archive_url = "https://exiftool.org/Image-ExifTool-12.70.tar.gz",
                search_file = "exiftool",
                install_name = "ExifTool",
                install_dir = programs.GetProgramInstallDir("ExifTool", "linux"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
