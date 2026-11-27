# Imports

# Local imports
from joybox import config
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase

# EKA2L1 emulator
class EKA2L1(emulatorbase.EmulatorBase):

    NAME = "EKA2L1"

    # Write its config files, verify the locker system files, then unzip the data archive
    # into each platform's setup dir, keeping files already there
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
            return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["data"]:
                if not self.extract_system_archive(platform, obj, setup_params):
                    return False
        return True

    # Run EKA2L1 with the game dir mounted and the game name as the app to start
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
            programs.get_emulator_program("EKA2L1"),
            "--mount", config.TOKEN_GAME_DIR,
            "--app", config.TOKEN_GAME_NAME
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
