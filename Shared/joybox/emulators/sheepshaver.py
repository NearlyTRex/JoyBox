# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import programs
from joybox import emulatorbase


# SheepShaver emulator
class SheepShaver(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "SheepShaver"

    # Get platforms
    def get_platforms(self):
        return []

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("SheepShaver", "windows"):
            success = release.download_github_release(
                github_user = "NearlyTRex",
                github_repo = "MacEmu",
                starts_with = "SheepShaver-Windows",
                ends_with = ".zip",
                search_file = "SheepShaver.exe",
                install_name = "SheepShaver",
                install_dir = programs.get_program_install_dir("SheepShaver", "windows"),
                backups_dir = programs.get_program_backup_dir("SheepShaver", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False

        # Download linux program
        if programs.should_program_be_installed("SheepShaver", "linux"):
            success = release.download_github_release(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "SheepShaver-x86_64",
                ends_with = ".AppImage",
                install_name = "SheepShaver",
                install_dir = programs.get_program_install_dir("SheepShaver", "linux"),
                backups_dir = programs.get_program_backup_dir("SheepShaver", "linux"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("SheepShaver", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("SheepShaver", "windows"),
                install_name = "SheepShaver",
                install_dir = programs.get_program_install_dir("SheepShaver", "windows"),
                search_file = "SheepShaver.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False

        # Setup linux program
        if programs.should_program_be_installed("SheepShaver", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("SheepShaver", "linux"),
                install_name = "SheepShaver",
                install_dir = programs.get_program_install_dir("SheepShaver", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup SheepShaver")
                return False
        return True
