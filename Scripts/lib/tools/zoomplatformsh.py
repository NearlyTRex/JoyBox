# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import release
import programs
import toolbase

# Config files
config_files = {}

# ZoomPlatformSH tool
class ZoomPlatformSH(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "ZoomPlatformSH"

    # Get config
    def get_config(self):
        return {
            "ZoomPlatformSH": {
                "program": "ZoomPlatformSH/lib/zoom-platform.sh"
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("ZoomPlatformSH"):
            success = release.download_github_release(
                github_user = "ZOOM-Platform",
                github_repo = "zoom-platform.sh",
                starts_with = "zoom-platform",
                ends_with = ".sh",
                search_file = "zoom-platform.sh",
                install_name = "ZoomPlatformSH",
                install_dir = programs.get_library_install_dir("ZoomPlatformSH", "lib"),
                backups_dir = programs.get_library_backup_dir("ZoomPlatformSH", "lib"),
                install_files = ["zoom-platform.sh"],
                release_type = config.ReleaseType.PROGRAM,
                chmod_files = [
                    {
                        "file": "zoom-platform.sh",
                        "perms": 755
                    }
                ],
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ZoomPlatformSH")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("ZoomPlatformSH"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("ZoomPlatformSH", "lib"),
                install_name = "ZoomPlatformSH",
                install_dir = programs.get_library_install_dir("ZoomPlatformSH", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ZoomPlatformSH")
                return False
        return True
