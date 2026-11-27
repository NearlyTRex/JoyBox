# Local imports
from joybox import config
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# BigPEmu emulator
class BigPEmu(emulatorbase.EmulatorBase):

    NAME = "BigPEmu"

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)

    # Run BigPEmu on the game file with -localdata so it keeps its data beside the program
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
            programs.get_emulator_program("BigPEmu"),
            config.TOKEN_GAME_FILE,
            "-localdata"
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
