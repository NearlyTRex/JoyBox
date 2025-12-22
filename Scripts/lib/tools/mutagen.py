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

# Mutagen tool
class Mutagen(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Mutagen"

    # Get config
    def GetConfig(self):
        return {
            "Mutagen": {
                "package_dir": "Mutagen/lib",
                "package_name": "mutagen"
            },
            "MutagenMP3": {
                "package_dir": "Mutagen/lib",
                "package_name": "mutagen.mp3"
            },
            "MutagenID3": {
                "package_dir": "Mutagen/lib",
                "package_name": "mutagen.id3"
            },
            "MutagenMP4": {
                "package_dir": "Mutagen/lib",
                "package_name": "mutagen.mp4"
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("Mutagen"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mutagen",
                output_dir = programs.GetLibraryInstallDir("Mutagen", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mutagen")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "Mutagen",
                output_dir = programs.GetLibraryBackupDir("Mutagen", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mutagen")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("Mutagen"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("Mutagen", "lib"),
                install_name = "Mutagen",
                install_dir = programs.GetLibraryInstallDir("Mutagen", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Mutagen")
                return False
        return True
