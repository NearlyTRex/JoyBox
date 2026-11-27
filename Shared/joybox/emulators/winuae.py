# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# WinUAE emulator
class WinUAE(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "WinUAE"

    # Get platforms
    def get_platforms(self):
        return []

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("WinUAE", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://www.winuae.net/download",
                webpage_base_url = "https://www.winuae.net",
                starts_with = "https://download.abime.net/winuae/releases/WinUAE",
                ends_with = "x64.zip",
                search_file = "winuae64.exe",
                install_name = "WinUAE",
                install_dir = programs.get_program_install_dir("WinUAE", "windows"),
                backups_dir = programs.get_program_backup_dir("WinUAE", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup WinUAE")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("WinUAE", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("WinUAE", "windows"),
                install_name = "WinUAE",
                install_dir = programs.get_program_install_dir("WinUAE", "windows"),
                search_file = "winuae64.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup WinUAE")
                return False
        return True
