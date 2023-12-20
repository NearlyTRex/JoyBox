# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# Mkpl tool
class Mkpl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mkpl"

    # Get config
    def GetConfig(self):
        return {
            "Mkpl": {
                "program": "Mkpl/mkpl.py"
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("Mkpl"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryInstallDir("Mkpl"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
