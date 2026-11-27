# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# Atari800 emulator
class Atari800(emulatorbase.EmulatorBase):

    NAME = "Atari800"

    # Windows SDL build from the atari800 GitHub release (pinned, not latest);
    # Linux AppImage built from the NearlyTRex/Atari800 fork with autotools
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Atari800", "windows"):
            success = release.download_github_release(
                github_user = "atari800",
                github_repo = "atari800",
                starts_with = "atari800",
                ends_with = "win32-sdl.zip",
                search_file = "atari800.exe",
                install_name = "Atari800",
                install_dir = programs.get_program_install_dir("Atari800", "windows"),
                backups_dir = programs.get_program_backup_dir("Atari800", "windows"),
                get_latest = False,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Atari800")
                return False

        # Build linux program
        if programs.should_program_be_installed("Atari800", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Atari800.git",
                output_file = "Atari800-x86_64.AppImage",
                install_name = "Atari800",
                install_dir = programs.get_program_install_dir("Atari800", "linux"),
                backups_dir = programs.get_program_backup_dir("Atari800", "linux"),
                build_cmd = [
                    "./autogen.sh",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/Atari800/act", "to": "AppImage/usr/bin"},
                    {"from": "Source/Atari800/src/atari800", "to": "AppImage/usr/bin/atari800"},
                    {"from": "Source/Atari800/debian/atari800.desktop", "to": "AppImage/atari800.desktop"},
                    {"from": "Source/Atari800/data/atari1.png", "to": "AppImage/atari800.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/atari800", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Atari800")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Atari800", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Atari800", "windows"),
                install_name = "Atari800",
                install_dir = programs.get_program_install_dir("Atari800", "windows"),
                search_file = "atari800.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Atari800")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Atari800", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Atari800", "linux"),
                install_name = "Atari800",
                install_dir = programs.get_program_install_dir("Atari800", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Atari800")
                return False
        return True

    # Write its config files under the emulators root
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
                logger.log_error("Could not setup Atari800 config files")
                return False
        return True

    # Run Atari800 on the game file
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
            programs.get_emulator_program("Atari800"),
            config.TOKEN_GAME_FILE
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
