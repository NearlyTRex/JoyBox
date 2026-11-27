# Local imports
from joybox import config
from joybox import logger
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import emulatorbase


# Stella emulator
class Stella(emulatorbase.EmulatorBase):

    NAME = "Stella"

    # Windows build from the stella-emu GitHub release; Linux AppImage built from the
    # NearlyTRex/Stella fork with autotools
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.download_github_release(
                github_user = "stella-emu",
                github_repo = "stella",
                starts_with = "Stella",
                ends_with = "windows.zip",
                search_file = "64-bit/Stella.exe",
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                backups_dir = programs.get_program_backup_dir("Stella", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False

        # Build linux program
        if programs.should_program_be_installed("Stella", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Stella.git",
                output_file = "Stella-x86_64.AppImage",
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "linux"),
                backups_dir = programs.get_program_backup_dir("Stella", "linux"),
                build_cmd = [
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/Stella/stella", "to": "AppImage/usr/bin/stella"},
                    {"from": "Source/Stella/src/os/unix/stella.desktop", "to": "AppImage/stella.desktop"},
                    {"from": "Source/Stella/src/common/stella.png", "to": "AppImage/stella.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/stella", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Stella", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Stella", "windows"),
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "windows"),
                search_file = "64-bit/Stella.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Stella", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Stella", "linux"),
                install_name = "Stella",
                install_dir = programs.get_program_install_dir("Stella", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Stella")
                return False
        return True
