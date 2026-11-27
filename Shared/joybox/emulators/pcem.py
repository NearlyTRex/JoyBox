# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# PCEm emulator
class PCEm(emulatorbase.EmulatorBase):

    NAME = "PCEm"

    # Download the Windows build from the sarah-walker-pcem GitHub release; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("PCEm", "windows"):
            success = release.download_github_release(
                github_user = "sarah-walker-pcem",
                github_repo = "pcem",
                starts_with = "PCem",
                ends_with = "Win.zip",
                search_file = "PCem.exe",
                install_name = "PCEm",
                install_dir = programs.get_program_install_dir("PCEm", "windows"),
                backups_dir = programs.get_program_backup_dir("PCEm", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCEm")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("PCEm", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PCEm", "windows"),
                install_name = "PCEm",
                install_dir = programs.get_program_install_dir("PCEm", "windows"),
                search_file = "PCem.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCEm")
                return False
        return True
