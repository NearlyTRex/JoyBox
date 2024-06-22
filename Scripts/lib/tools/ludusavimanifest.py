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

# LudusaviManifest tool
class LudusaviManifest(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "LudusaviManifest"

    # Get config
    def GetConfig(self):
        return {
            "LudusaviManifest": {
                "program": "LudusaviManifest/lib/data/manifest.yaml"
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup LudusaviManifest")
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup LudusaviManifest")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                install_name = "LudusaviManifest",
                install_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup LudusaviManifest")
