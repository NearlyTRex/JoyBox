# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# CxBxReloaded emulator
class CxBxReloaded(emulatorbase.EmulatorBase):

    NAME = "CxBxReloaded"

    # Download the Windows build from the Cxbx-Reloaded GitHub release; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("CxBxReloaded", "windows"):
            success = release.download_github_release(
                github_user = "Cxbx-Reloaded",
                github_repo = "Cxbx-Reloaded",
                starts_with = "CxbxReloaded-Release",
                ends_with = ".zip",
                search_file = "cxbx.exe",
                install_name = "CxBxReloaded",
                install_dir = programs.get_program_install_dir("CxBxReloaded", "windows"),
                backups_dir = programs.get_program_backup_dir("CxBxReloaded", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CxBxReloaded")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("CxBxReloaded", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("CxBxReloaded", "windows"),
                install_name = "CxBxReloaded",
                install_dir = programs.get_program_install_dir("CxBxReloaded", "windows"),
                search_file = "cxbx.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup CxBxReloaded")
                return False
        return True
