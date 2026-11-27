# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import programs
from joybox import release
from joybox import toolbase


# ExifTool tool
class ExifTool(toolbase.ToolBase):

    NAME = "ExifTool"

    # Clone the NearlyTRex/ExifTool repo at its configured branch into its lib dir,
    # then archive the repo into its backups dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("ExifTool"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                github_branch = programs.get_tool_config_value("ExifTool", "github_branch"),
                output_dir = programs.get_library_install_dir("ExifTool", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "ExifTool",
                github_branch = programs.get_tool_config_value("ExifTool", "github_branch"),
                output_dir = programs.get_library_backup_dir("ExifTool", "lib"),
                recursive = True,
                clean = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
        return True

    # Install the library from the repo archive stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("ExifTool"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("ExifTool", "lib"),
                install_name = "ExifTool",
                install_dir = programs.get_library_install_dir("ExifTool", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup ExifTool")
                return False
        return True
