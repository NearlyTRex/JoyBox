# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# ExifTool tool
class ExifTool(toolbase.ToolBase):

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("ExifTool"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                output_dir = programs.GetLibraryInstallDir("ExifTool"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
