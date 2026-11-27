# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import toolbase


# ZoomPlatformSH tool
class ZoomPlatformSH(toolbase.ToolBase):

    NAME = "ZoomPlatformSH"

    # Download the latest zoom-platform.sh script from the ZOOM-Platform GitHub release
    # and mark it executable
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ZoomPlatformSH")
                return False
        return True

    # Install the script from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("ZoomPlatformSH"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("ZoomPlatformSH", "lib"),
                install_name = "ZoomPlatformSH",
                install_dir = programs.get_library_install_dir("ZoomPlatformSH", "lib"),
                search_file = "zoom-platform.sh",
                install_files = ["zoom-platform.sh"],
                release_type = config.ReleaseType.PROGRAM,
                chmod_files = [
                    {
                        "file": "zoom-platform.sh",
                        "perms": 755
                    }
                ],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ZoomPlatformSH")
                return False
        return True
