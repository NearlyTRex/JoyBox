# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# Demul emulator
class Demul(emulatorbase.EmulatorBase):

    NAME = "Demul"

    # Download the Windows 7z linked from the demul.emulation64.com downloads page; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Demul", "windows"):
            success = release.download_webpage_release(
                webpage_url = "http://demul.emulation64.com/downloads/",
                webpage_base_url = "http://demul.emulation64.com",
                starts_with = "http://demul.emulation64.com/files/demul",
                ends_with = ".7z",
                search_file = "demul.exe",
                install_name = "Demul",
                install_dir = programs.get_program_install_dir("Demul", "windows"),
                backups_dir = programs.get_program_backup_dir("Demul", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Demul")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Demul", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Demul", "windows"),
                install_name = "Demul",
                install_dir = programs.get_program_install_dir("Demul", "windows"),
                search_file = "demul.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Demul")
                return False
        return True
