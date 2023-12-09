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

# PSVTools tool
class PSVTools(base.ToolBase):

    # Get name
    def GetName(self):
        return "PSVTools"

    # Get config
    def GetConfig(self):
        return {
            "PSVTools": {
                "program": "PSVTools/main.py"
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("PSVTools"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                output_dir = programs.GetLibraryInstallDir("PSVTools"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
