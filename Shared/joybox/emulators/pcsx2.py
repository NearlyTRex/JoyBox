# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# PCSX2 emulator
class PCSX2(emulatorbase.EmulatorBase):

    NAME = "PCSX2"

    # Download the Windows Qt 7z and Linux AppImage from the PCSX2 GitHub release
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("PCSX2", "windows"):
            success = release.download_github_release(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = "windows-x64-Qt.7z",
                search_file = "pcsx2-qt.exe",
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "windows"),
                backups_dir = programs.get_program_backup_dir("PCSX2", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False

        # Download linux program
        if programs.should_program_be_installed("PCSX2", "linux"):
            success = release.download_github_release(
                github_user = "PCSX2",
                github_repo = "pcsx2",
                starts_with = "pcsx2",
                ends_with = ".AppImage",
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "linux"),
                backups_dir = programs.get_program_backup_dir("PCSX2", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("PCSX2", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PCSX2", "windows"),
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "windows"),
                search_file = "pcsx2-qt.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False

        # Setup linux program
        if programs.should_program_be_installed("PCSX2", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("PCSX2", "linux"),
                install_name = "PCSX2",
                install_dir = programs.get_program_install_dir("PCSX2", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2")
                return False
        return True

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup PCSX2 config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("PCSX2"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("PCSX2", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup PCSX2 system files")
                    return False
        return True

    # Run PCSX2 on the game file, with -fullscreen when asked
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("PCSX2"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "-fullscreen"
            ]

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
