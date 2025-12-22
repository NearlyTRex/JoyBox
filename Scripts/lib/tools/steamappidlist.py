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

# SteamAppIDList tool
class SteamAppIDList(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "SteamAppIDList"

    # Get config
    def get_config(self):
        return {
            "SteamAppIDList": {
                "csv": "SteamAppIDList/lib/steamcmd_appid.csv"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("SteamAppIDList"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "SteamAppIDList",
                output_dir = programs.get_library_install_dir("SteamAppIDList", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamAppIDList")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "SteamAppIDList",
                output_dir = programs.get_library_backup_dir("SteamAppIDList", "lib"),
                recursive = True,
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamAppIDList")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("SteamAppIDList"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("SteamAppIDList", "lib"),
                install_name = "SteamAppIDList",
                install_dir = programs.get_library_install_dir("SteamAppIDList", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SteamAppIDList")
                return False
        return True
