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


# MGBA emulator
class MGBA(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "mGBA"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.NINTENDO_GAME_BOY_ADVANCE,
            config.Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER,
            config.Platform.NINTENDO_GAME_BOY,
            config.Platform.NINTENDO_GAME_BOY_COLOR,
            config.Platform.NINTENDO_SUPER_GAME_BOY,
            config.Platform.NINTENDO_SUPER_GAME_BOY_COLOR
        ]

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("mGBA", "windows"):
            success = release.download_github_release(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = "win64.7z",
                search_file = "mGBA.exe",
                install_name = "mGBA",
                install_dir = programs.get_program_install_dir("mGBA", "windows"),
                backups_dir = programs.get_program_backup_dir("mGBA", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup mGBA")
                return False

        # Download linux program
        if programs.should_program_be_installed("mGBA", "linux"):
            success = release.download_github_release(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = ".appimage",
                install_name = "mGBA",
                install_dir = programs.get_program_install_dir("mGBA", "linux"),
                backups_dir = programs.get_program_backup_dir("mGBA", "linux"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup mGBA")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("mGBA", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("mGBA", "windows"),
                install_name = "mGBA",
                install_dir = programs.get_program_install_dir("mGBA", "windows"),
                search_file = "mGBA.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup mGBA")
                return False

        # Setup linux program
        if programs.should_program_be_installed("mGBA", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("mGBA", "linux"),
                install_name = "mGBA",
                install_dir = programs.get_program_install_dir("mGBA", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup mGBA")
                return False
        return True

    # Configure
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
                logger.log_error("Could not setup mGBA config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("mGBA"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("mGBA", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup mGBA system files")
                    return False
        return True

    # Launch
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
            programs.get_emulator_program("mGBA"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen"
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
