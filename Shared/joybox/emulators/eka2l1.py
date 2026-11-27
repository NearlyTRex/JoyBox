# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import archive
from joybox import emulatorcommon
from joybox import emulatorbase

# Unzip the locker's data archive into the platform's setup dir, keeping files
# already there; True when the locker has no such archive
def extract_system_archive(platform, obj, setup_params):
    if not os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("EKA2L1"), obj + config.ArchiveFileType.ZIP.cval())):
        return True
    success = archive.extract_archive(
        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("EKA2L1"), obj + config.ArchiveFileType.ZIP.cval()),
        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("EKA2L1", "setup_dir", platform), obj),
        skip_existing = True,
        verbose = setup_params.verbose,
        pretend_run = setup_params.pretend_run,
        exit_on_failure = setup_params.exit_on_failure)
    if not success:
        logger.log_error("Could not extract EKA2L1 system files")
        return False
    return True

# EKA2L1 emulator
class EKA2L1(emulatorbase.EmulatorBase):

    NAME = "EKA2L1"

    # Write its config files, verify the locker system files, then unzip the data archive
    # into each platform's setup dir, keeping files already there
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
                logger.log_error("Could not setup EKA2L1 config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["data"]:
                if not extract_system_archive(platform, obj, setup_params):
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
