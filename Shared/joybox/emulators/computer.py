# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import emulatorbase
from joybox import computer
from joybox import platform_info


# Computer emulator
class Computer(emulatorbase.EmulatorBase):

    NAME = "Computer"

    # Sandboxie on Windows, Wine elsewhere, since computer games save inside their sandbox
    def get_save_type(self):
        if platform_info.is_windows_platform():
            return config.SaveType.SANDBOXIE
        return config.SaveType.WINE

    # Always None: computer games have no single emulator config file
    def get_config_file(self, emulator_platform = None):
        return None

    # Always None: saves live in each game's sandbox, not an emulator dir
    def get_save_base_dir(self, emulator_platform = None):
        return None

    # Always None: there are no per-platform save subdirs
    def get_save_sub_dirs(self, emulator_platform = None):
        return None

    # Always None: saves live in each game's sandbox, not an emulator dir
    def get_save_dir(self, game_platform, emulator_platform = None):
        return None

    # Write the DOSBox-X and ScummVM config files under the emulators root
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
                logger.log_error("Could not setup DosBoxX/ScummVM config files")
                return False
        return True

    # Hand the game to the computer launcher, which runs it inside a Wine prefix on Linux or Sandboxie on Windows
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Launch game
        return computer.launch_computer_game(
            game_info = game_info,
            capture_type = capture_type,
            capture_file = capture_file,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
