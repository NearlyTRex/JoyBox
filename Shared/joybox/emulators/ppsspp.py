# Local imports
from joybox import config
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# PPSSPP emulator
class PPSSPP(emulatorbase.EmulatorBase):

    NAME = "PPSSPP"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)

    # Run PPSSPP on the game file
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
            programs.get_emulator_program("PPSSPP"),
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
