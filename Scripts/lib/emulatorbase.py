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
    def GetName(self):
        return ""

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {}

    # Get config file
    def GetConfigFile(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.GetName(),
            program_key = "config_file",
            program_platform = emulator_platform)

    # Get setup dir
    def GetSetupDir(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.GetName(),
            program_key = "setup_dir",
            program_platform = emulator_platform)

    # Get save type
    def GetSaveType(self):
        return None

    # Get save base dir
    def GetSaveBaseDir(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.GetName(),
            program_key = "save_base_dir",
            program_platform = emulator_platform)

    # Get save sub dirs
    def GetSaveSubDirs(self, emulator_platform = None):
        return programs.GetConfigValue(
            program_config = self.GetConfig(),
            program_name = self.GetName(),
            program_key = "save_sub_dirs",
            program_platform = emulator_platform)

    # Get save dir
    def GetSaveDir(self, game_platform, emulator_platform = None):

        # Use current platform if none specified
        if not emulator_platform:
            emulator_platform = environment.get_current_platform()

        # Get basic saves dir
        saves_dir = programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.GetName(),
            program_key = "save_dir",
            program_platform = emulator_platform)

        # Get base dir and sub dirs
        saves_base_dir = self.GetSaveBaseDir(emulator_platform)
        save_sub_dirs = self.GetSaveSubDirs(emulator_platform)

        # Construct actual saves dir
        if saves_base_dir and save_sub_dirs and game_platform:
            if game_platform in save_sub_dirs.keys():
                return paths.join_paths(saves_base_dir, save_sub_dirs[game_platform])
        return saves_dir

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        return True

    # Setup
    def Setup(self, setup_params = None):
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        return True

    # Configure
    def Configure(self, setup_params = None):
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        return False
