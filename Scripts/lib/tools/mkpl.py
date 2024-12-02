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

# Mkpl tool
class Mkpl(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mkpl"

    # Get config
    def GetConfig(self):
        return {
            "Mkpl": {
                "program": "Mkpl/lib/mkpl.py"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("Mkpl"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryInstallDir("Mkpl", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mkpl")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mkpl",
                output_dir = programs.GetLibraryBackupDir("Mkpl", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mkpl")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("Mkpl"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Mkpl", "lib"),
                install_name = "Mkpl",
                install_dir = programs.GetLibraryInstallDir("Mkpl", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mkpl")
