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
                "program": "ExifTool/exiftool"
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("ExifTool"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.GetLibraryInstallDir("ExifTool"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
