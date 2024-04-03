# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# XCITrimmer tool
class XCITrimmer(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "XCITrimmer"

    # Get config
    def GetConfig(self):
        return {
            "XCITrimmer": {
                "program": "XCITrimmer/lib/XCI_Trimmer.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("XCITrimmer"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XCITrimmer",
                output_dir = programs.GetLibraryInstallDir("XCITrimmer", "lib"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XCITrimmer")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "XCITrimmer",
                output_dir = programs.GetLibraryBackupDir("XCITrimmer", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XCITrimmer")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("XCITrimmer"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("XCITrimmer", "lib"),
                install_name = "XCITrimmer",
                install_dir = programs.GetLibraryInstallDir("XCITrimmer", "lib"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup XCITrimmer")
