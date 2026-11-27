# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import release
from joybox import requirements
from joybox import programs
from joybox import toolbase


# PSNGetPkgInfo tool
class PSNGetPkgInfo(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "PSNGetPkgInfo"

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("PSNGetPkgInfo"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PSNGetPkgInfo",
                github_branch = programs.get_tool_config_value("PSNGetPkgInfo", "github_branch"),
                output_dir = programs.get_library_install_dir("PSNGetPkgInfo", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSNGetPkgInfo")
                return False
            success = requirements.setup_tool_requirements(
                tool_name = "PSNGetPkgInfo",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSNGetPkgInfo")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PSNGetPkgInfo",
                github_branch = programs.get_tool_config_value("PSNGetPkgInfo", "github_branch"),
                output_dir = programs.get_library_backup_dir("PSNGetPkgInfo", "lib"),
                recursive = True,
                clean = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSNGetPkgInfo")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("PSNGetPkgInfo"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("PSNGetPkgInfo", "lib"),
                install_name = "PSNGetPkgInfo",
                install_dir = programs.get_library_install_dir("PSNGetPkgInfo", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSNGetPkgInfo")
                return False
            success = requirements.setup_tool_requirements_offline(
                tool_name = "PSNGetPkgInfo",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PSNGetPkgInfo")
                return False
        return True
