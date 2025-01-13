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

# Get manifest
def GetManifest():
    return programs.GetToolPathConfigValue("LudusaviManifest", "manifest")

# LudusaviManifest tool
class LudusaviManifest(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "LudusaviManifest"

    # Get config
    def GetConfig(self):
        return {
            "LudusaviManifest": {
                "manifest": "LudusaviManifest/lib/data/manifest.yaml"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup LudusaviManifest")
				return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup LudusaviManifest")
				return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                install_name = "LudusaviManifest",
                install_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup LudusaviManifest")
				return False
        return True
