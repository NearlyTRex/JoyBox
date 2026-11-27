# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import release
from joybox import programs
from joybox import toolbase


# LudusaviManifest tool
class LudusaviManifest(toolbase.ToolBase):

    NAME = "LudusaviManifest"

    # Clone the NearlyTRex/LudusaviManifest repo at its configured branch into its lib dir,
    # then archive the repo into its backups dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("LudusaviManifest"):
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                github_branch = programs.get_tool_config_value("LudusaviManifest", "github_branch"),
                output_dir = programs.get_library_install_dir("LudusaviManifest", "lib"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
            success = network.archive_github_repository(
                github_user = "NearlyTRex",
                github_repo = "LudusaviManifest",
                github_branch = programs.get_tool_config_value("LudusaviManifest", "github_branch"),
                output_dir = programs.get_library_backup_dir("LudusaviManifest", "lib"),
                recursive = True,
                clean = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
        return True

    # Install the library from the repo archive stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("LudusaviManifest"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("LudusaviManifest", "lib"),
                install_name = "LudusaviManifest",
                install_dir = programs.get_library_install_dir("LudusaviManifest", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup LudusaviManifest")
                return False
        return True
