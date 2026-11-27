# Local imports
from joybox import config
from joybox import environment
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# BasiliskII emulator
class BasiliskII(emulatorbase.EmulatorBase):

    NAME = "BasiliskII"

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
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
