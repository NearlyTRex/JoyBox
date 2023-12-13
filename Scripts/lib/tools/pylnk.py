# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# PyLnk tool
class PyLnk(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PyLnk"

    # Get config
    def GetConfig(self):
        return {
            "PyLnk": {
                "program": "PyLnk/pylnk3.py"
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("PyLnk"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "PyLnk",
                output_dir = programs.GetLibraryInstallDir("PyLnk"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
