# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import release
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
                "yaml": "LudusaviManifest/lib/data/manifest.yaml"
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                output_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("LudusaviManifest"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("LudusaviManifest", "lib"),
                install_name = "LudusaviManifest",
                install_dir = programs.GetLibraryInstallDir("LudusaviManifest", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
        return True
