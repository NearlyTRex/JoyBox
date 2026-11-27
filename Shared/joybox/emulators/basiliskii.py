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


# BasiliskII emulator
class BasiliskII(emulatorbase.EmulatorBase):

    NAME = "BasiliskII"

    # Windows build from the NearlyTRex/MacEmu GitHub release; Linux AppImage from Korkman/macemu-appimage-builder
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("BasiliskII", "windows"):
            success = release.download_github_release(
                github_user = "NearlyTRex",
                github_repo = "MacEmu",
                starts_with = "BasiliskII-Windows",
                ends_with = ".zip",
                search_file = "BasiliskII.exe",
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "windows"),
                backups_dir = programs.get_program_backup_dir("BasiliskII", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False

        # Download linux program
        if programs.should_program_be_installed("BasiliskII", "linux"):
            success = release.download_github_release(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "BasiliskII-x86_64",
                ends_with = ".AppImage",
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "linux"),
                backups_dir = programs.get_program_backup_dir("BasiliskII", "linux"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BasiliskII", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BasiliskII", "windows"),
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "windows"),
                search_file = "BasiliskII.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False

        # Setup linux program
        if programs.should_program_be_installed("BasiliskII", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BasiliskII", "linux"),
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
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
                logger.log_error("Could not setup BasiliskII config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("BasiliskII"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("BasiliskII", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup BasiliskII system files")
                    return False
        return True

    # Run BasiliskII with the game as its --disk; fullscreen hides the GUI with --nogui
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
            programs.get_emulator_program("BasiliskII"),
            "--disk", config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--nogui", "true"
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
