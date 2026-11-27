# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import toolbase


# GeckoDriver tool
class GeckoDriver(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "GeckoDriver"

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("GeckoDriver", "windows"):
            success = release.download_github_release(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "win32.zip",
                search_file = "geckodriver.exe",
                install_name = "GeckoDriver",
                install_dir = programs.get_program_install_dir("GeckoDriver", "windows"),
                backups_dir = programs.get_program_backup_dir("GeckoDriver", "windows"),
                install_files = ["geckodriver.exe"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GeckoDriver")
                return False

        # Download linux program
        if programs.should_program_be_installed("GeckoDriver", "linux"):
            success = release.download_github_release(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "linux64.tar.gz",
                search_file = "geckodriver",
                install_name = "GeckoDriver",
                install_dir = programs.get_program_install_dir("GeckoDriver", "linux"),
                backups_dir = programs.get_program_backup_dir("GeckoDriver", "linux"),
                install_files = ["geckodriver"],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GeckoDriver")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("GeckoDriver", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("GeckoDriver", "windows"),
                install_name = "GeckoDriver",
                install_dir = programs.get_program_install_dir("GeckoDriver", "windows"),
                search_file = "geckodriver.exe",
                install_files = ["geckodriver.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GeckoDriver")
                return False

        # Setup linux program
        if programs.should_program_be_installed("GeckoDriver", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("GeckoDriver", "linux"),
                install_name = "GeckoDriver",
                install_dir = programs.get_program_install_dir("GeckoDriver", "linux"),
                search_file = "geckodriver",
                install_files = ["geckodriver"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup GeckoDriver")
                return False
        return True
