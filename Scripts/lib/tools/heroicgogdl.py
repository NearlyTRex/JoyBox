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

# HeroicGogDL tool
class HeroicGogDL(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "HeroicGogDL"

    # Get config
    def get_config(self):
        return {
            "HeroicGogDL": {
                "program": "HeroicGogDL/lib/main.py",
                "login_script": "HeroicGogDL/lib/login.py",
                "auth_json": "HeroicGogDL/lib/auth.json"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("HeroicGogDL"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HeroicGogDL",
                output_dir = programs.GetLibraryInstallDir("HeroicGogDL", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HeroicGogDL")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HeroicGogDL",
                output_dir = programs.GetLibraryBackupDir("HeroicGogDL", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HeroicGogDL")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("HeroicGogDL"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("HeroicGogDL", "lib"),
                install_name = "HeroicGogDL",
                install_dir = programs.GetLibraryInstallDir("HeroicGogDL", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup HeroicGogDL")
                return False
        return True
