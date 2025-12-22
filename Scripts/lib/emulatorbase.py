# Imports
import os, os.path
import sys

# Local imports
import config
import programs
import environment
import paths

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
            emulator_platform = environment.get_current_platform()

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
