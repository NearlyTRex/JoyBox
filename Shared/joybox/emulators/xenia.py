# Local imports
from joybox import config
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# Xenia emulator
class Xenia(emulatorbase.EmulatorBase):

    NAME = "Xenia"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)

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
