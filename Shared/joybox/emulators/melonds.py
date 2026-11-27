# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# MelonDS emulator
class MelonDS(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "melonDS"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.NINTENDO_DS,
            config.Platform.NINTENDO_DSI
        ]

    # Setup
    def setup(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("melonDS", "windows"):
            success = release.download_github_release(
                github_user = "melonDS-emu",
                github_repo = "melonDS",
                starts_with = "melonDS",
                ends_with = "windows-x86_64.zip",
                search_file = "melonDS.exe",
                install_name = "melonDS",
                install_dir = programs.get_program_install_dir("melonDS", "windows"),
                backups_dir = programs.get_program_backup_dir("melonDS", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False

        # Build linux program
        if programs.should_program_be_installed("melonDS", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/melonDS.git",
                output_file = "melonDS-x86_64.AppImage",
                install_name = "melonDS",
                install_dir = programs.get_program_install_dir("melonDS", "linux"),
                backups_dir = programs.get_program_backup_dir("melonDS", "linux"),
                build_cmd = [
                    "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/melonDS/Build/melonDS", "to": "AppImage/usr/bin/melonDS"},
                    {"from": "Source/melonDS/res/net.kuribo64.melonDS.desktop", "to": "AppImage/net.kuribo64.melonDS.desktop"},
                    {"from": "Source/melonDS/res/icon/melon_256x256.png", "to": "AppImage/net.kuribo64.melonDS.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/melonDS", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("melonDS", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("melonDS", "windows"),
                install_name = "melonDS",
                install_dir = programs.get_program_install_dir("melonDS", "windows"),
                search_file = "melonDS.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False

        # Setup linux program
        if programs.should_program_be_installed("melonDS", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("melonDS", "linux"),
                install_name = "melonDS",
                install_dir = programs.get_program_install_dir("melonDS", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):

        # Use default params if not provided
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
                logger.log_error("Could not setup melonDS config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("melonDS"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("melonDS", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup melonDS system files")
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
            programs.get_emulator_program("melonDS"),
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
