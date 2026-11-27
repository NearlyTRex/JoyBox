# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# BlastEm emulator
class BlastEm(emulatorbase.EmulatorBase):

    NAME = "BlastEm"

    # Download the Windows zip linked from the retrodev.com BlastEm page; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("BlastEm", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://www.retrodev.com/blastem",
                webpage_base_url = "https://www.retrodev.com/blastem/",
                starts_with = "https://www.retrodev.com/blastem/blastem-win32",
                ends_with = ".zip",
                search_file = "blastem.exe",
                install_name = "BlastEm",
                install_dir = programs.get_program_install_dir("BlastEm", "windows"),
                backups_dir = programs.get_program_backup_dir("BlastEm", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BlastEm")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BlastEm", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BlastEm", "windows"),
                install_name = "BlastEm",
                install_dir = programs.get_program_install_dir("BlastEm", "windows"),
                search_file = "blastem.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BlastEm")
                return False
        return True
