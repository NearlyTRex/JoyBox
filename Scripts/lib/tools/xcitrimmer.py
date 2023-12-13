# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# XCITrimmer tool
class XCITrimmer(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "XCITrimmer"

    # Get config
    def GetConfig(self):
        return {
            "XCITrimmer": {
                "program": "XCITrimmer/XCI_Trimmer.py"
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("XCITrimmer"):
            network.DownloadLatestGithubSource(
                github_user = "NearlyTRex",
                github_repo = "XCITrimmer",
                output_dir = programs.GetLibraryInstallDir("XCITrimmer"),
                clean_first = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

