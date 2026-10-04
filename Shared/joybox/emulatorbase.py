# Local imports
import joybox.programs as programs
import joybox.environment as environment
import joybox.paths as paths
import joybox.hashing as hashing
import joybox.logger as logger
from joybox import platform_info

# Base emulator
class EmulatorBase:

    # Get name
    def get_name(self):
        return ""

    # Get platforms
    def get_platforms(self):
        return []

    # Get config
    def get_config(self):
        return {}

    # Get config file
    def get_config_file(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "config_file",
            program_platform = emulator_platform)

    # Get setup dir
    def get_setup_dir(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "setup_dir",
            program_platform = emulator_platform)

    # Get save type
    def get_save_type(self):
        return None

    # Get save base dir
    def get_save_base_dir(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "save_base_dir",
            program_platform = emulator_platform)

    # Get save sub dirs
    def get_save_sub_dirs(self, emulator_platform = None):
        return programs.get_config_value(
            program_config = self.get_config(),
            program_name = self.get_name(),
            program_key = "save_sub_dirs",
            program_platform = emulator_platform)

    # Get save dir
    def get_save_dir(self, game_platform, emulator_platform = None):

        # Use current platform if none specified
        if not emulator_platform:
            emulator_platform = platform_info.get_current_platform()

        # Get basic saves dir
        saves_dir = programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "save_dir",
            program_platform = emulator_platform)

        # Get base dir and sub dirs
        saves_base_dir = self.get_save_base_dir(emulator_platform)
        save_sub_dirs = self.get_save_sub_dirs(emulator_platform)

        # Construct actual saves dir
        if saves_base_dir and save_sub_dirs and game_platform:
            if game_platform in save_sub_dirs.keys():
                return paths.join_paths(saves_base_dir, save_sub_dirs[game_platform])
        return saves_dir

    # Install add-ons
    def install_addons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        return True

    # Setup
    def setup(self, setup_params = None):
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        return True

    # Configure
    def configure(self, setup_params = None):
        return True

    # Verify locker system files against their expected md5s
    def verify_system_files(self, system_files, setup_params):
        setup_dir = environment.get_locker_gaming_emulator_setup_dir(self.get_name())
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.calculate_file_md5(
                src = paths.join_paths(setup_dir, filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)

            # Pretend runs read nothing, so there is no hash to compare
            if not setup_params.pretend_run and expected_md5 != actual_md5:
                logger.log_error("Could not verify %s system file %s" % (self.get_name(), filename))
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
        return False
