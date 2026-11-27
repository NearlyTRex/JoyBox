# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# SameBoy emulator
class SameBoy(emulatorbase.EmulatorBase):

    NAME = "SameBoy"

    # Download the Windows SDL build from the LIJI32/SameBoy GitHub release; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("SameBoy", "windows"):
            success = release.download_github_release(
                github_user = "LIJI32",
                github_repo = "SameBoy",
                starts_with = "sameboy_winsdl",
                ends_with = ".zip",
                search_file = "sameboy.exe",
                install_name = "SameBoy",
                install_dir = programs.get_program_install_dir("SameBoy", "windows"),
                backups_dir = programs.get_program_backup_dir("SameBoy", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("SameBoy", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("SameBoy", "windows"),
                install_name = "SameBoy",
                install_dir = programs.get_program_install_dir("SameBoy", "windows"),
                search_file = "sameboy.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SameBoy")
                return False
        return True
