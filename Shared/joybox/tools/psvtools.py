# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import release
from joybox import requirements
from joybox import programs
from joybox import toolbase


# PSVTools tool
class PSVTools(toolbase.ToolBase):

    NAME = "PSVTools"

    # Clone the NearlyTRex/PSVTools repo at its configured branch into its lib dir, install its
    # Python requirements, then archive the repo into its backups dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("PSVTools"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                github_branch = programs.get_tool_config_value("PSVTools", "github_branch"),
                output_dir = programs.get_library_install_dir("PSVTools", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
            success = requirements.setup_tool_requirements(
                tool_name = "PSVTools",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PSVTools",
                github_branch = programs.get_tool_config_value("PSVTools", "github_branch"),
                output_dir = programs.get_library_backup_dir("PSVTools", "lib"),
                recursive = True,
                clean = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
        return True

    # Install the library from the repo archive stored in its backups dir, then its Python requirements offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("PSVTools"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("PSVTools", "lib"),
                install_name = "PSVTools",
                install_dir = programs.get_library_install_dir("PSVTools", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
            success = requirements.setup_tool_requirements_offline(
                tool_name = "PSVTools",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSVTools")
                return False
        return True
