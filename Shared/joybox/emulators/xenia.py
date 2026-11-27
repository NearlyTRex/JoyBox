# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# Xenia emulator
class Xenia(emulatorbase.EmulatorBase):

    NAME = "Xenia"

    # Download the master Windows build from the xenia-project release-builds-windows GitHub release; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Xenia", "windows"):
            success = release.download_github_release(
                github_user = "xenia-project",
                github_repo = "release-builds-windows",
                starts_with = "xenia_master",
                ends_with = "master.zip",
                search_file = "xenia.exe",
                install_name = "Xenia",
                install_dir = programs.get_program_install_dir("Xenia", "windows"),
                backups_dir = programs.get_program_backup_dir("Xenia", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xenia")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Xenia", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Xenia", "windows"),
                install_name = "Xenia",
                install_dir = programs.get_program_install_dir("Xenia", "windows"),
                search_file = "xenia.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xenia")
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
                logger.log_error("Could not setup Xenia config files")
                return False
        return True

    # Run Xenia on the game file, with --fullscreen=true when asked
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
            programs.get_emulator_program("Xenia"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=true"
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
