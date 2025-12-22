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

# PySimpleGUI tool
class PySimpleGUI(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "PySimpleGUI"

    # Get config
    def get_config(self):
        return {
            "PySimpleGUI": {
                "program": "PySimpleGUI/lib/PySimpleGUI.py"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("PySimpleGUI"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySimpleGUI",
                output_dir = programs.GetLibraryInstallDir("PySimpleGUI", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySimpleGUI")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "PySimpleGUI",
                output_dir = programs.GetLibraryBackupDir("PySimpleGUI", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySimpleGUI")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("PySimpleGUI"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("PySimpleGUI", "lib"),
                install_name = "PySimpleGUI",
                install_dir = programs.GetLibraryInstallDir("PySimpleGUI", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PySimpleGUI")
                return False
        return True
