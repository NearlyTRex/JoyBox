# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import environment
from joybox import fileops
from joybox import toolbase
from joybox import platform_info


# AppImageTool tool
class AppImageTool(toolbase.ToolBase):

    NAME = "AppImageTool"

    # Download the Linux AppImage from the AppImage/AppImageKit GitHub release; Linux only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download linux program
        if programs.should_program_be_installed("AppImageTool", "linux"):
            success = release.download_github_release(
                github_user = "AppImage",
                github_repo = "AppImageKit",
                starts_with = "appimagetool-x86_64",
                ends_with = ".AppImage",
                search_file = "AppImageTool.AppImage",
                install_name = "AppImageTool",
                install_dir = programs.get_program_install_dir("AppImageTool", "linux"),
                backups_dir = programs.get_program_backup_dir("AppImageTool", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # Install the Linux AppImage from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup linux program
        if programs.should_program_be_installed("AppImageTool", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("AppImageTool", "linux"),
                install_name = "AppImageTool",
                install_dir = programs.get_program_install_dir("AppImageTool", "linux"),
                search_file = "AppImageTool.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # On Linux, copy the default icon into its install dir and write its config files under the tools root
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Copy icon
        if platform_info.is_linux_platform():
            success = fileops.copy_file_or_directory(
                src = paths.join_paths(environment.get_scripts_icons_dir(), "BostonIcons", "128", "mimes", "application-x-executable-script.svg"),
                dest = paths.join_paths(programs.get_program_install_dir("AppImageTool", "linux"), "icon.svg"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not copy AppImageTool icons")
                return False

        # Create config files
        if platform_info.is_linux_platform():
            for config_filename, config_contents in self.get_config_files().items():
                success = fileops.touch_file(
                    src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not create AppImageTool config files")
                    return False
        return True
