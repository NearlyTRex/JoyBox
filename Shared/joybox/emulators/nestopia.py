# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# Nestopia emulator
class Nestopia(emulatorbase.EmulatorBase):

    NAME = "Nestopia"

    # Download the Windows build from the 0ldsk00l/nestopia GitHub release; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Nestopia", "windows"):
            success = release.download_github_release(
                github_user = "0ldsk00l",
                github_repo = "nestopia",
                starts_with = "nestopia",
                ends_with = "win32.zip",
                search_file = "nestopia.exe",
                install_name = "Nestopia",
                install_dir = programs.get_program_install_dir("Nestopia", "windows"),
                backups_dir = programs.get_program_backup_dir("Nestopia", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nestopia")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Nestopia", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Nestopia", "windows"),
                install_name = "Nestopia",
                install_dir = programs.get_program_install_dir("Nestopia", "windows"),
                search_file = "nestopia.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Nestopia")
                return False
        return True
