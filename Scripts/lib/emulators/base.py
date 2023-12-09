# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import programs
import environment

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

    # Get save format
    def GetSaveFormat(self):
        return None

    # Get config file
    def GetConfigFile(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.GetEmulatorsRootDir(),
            program_name = self.GetName(),
            program_key = "config_file",
            program_platform = emulator_platform)

    # Get save base dir
    def GetSaveBaseDir(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.GetEmulatorsRootDir(),
            program_name = self.GetName(),
            program_key = "save_base_dir",
            program_platform = emulator_platform)

    # Get save sub dirs
    def GetSaveSubDirs(self, emulator_platform = None):
        return programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.GetEmulatorsRootDir(),
            program_name = self.GetName(),
            program_key = "save_sub_dirs",
            program_platform = emulator_platform)

    # Get save dir
    def GetSaveDir(self, emulator_platform = None):

        # Use current platform if none specified
        if not emulator_platform:
            emulator_platform = environment.GetCurrentPlatform()

        # Get basic saves dir
        saves_dir = programs.GetPathConfigValue(
            program_config = self.GetConfig(),
            base_dir = environment.GetEmulatorsRootDir(),
            program_name = self.GetName(),
            program_key = "save_dir",
            program_platform = emulator_platform)

        # Get base dir and sub dirs
        saves_base_dir = self.GetSaveBaseDir(emulator_platform)
        save_sub_dirs = self.GetSaveSubDirs(emulator_platform)

        # Construct actual saves dir
        if saves_base_dir and save_sub_dirs and emulator_platform:
            if emulator_platform in save_sub_dirs.keys():
                return os.path.join(saves_base_dir, save_sub_dirs[emulator_platform])
        return saves_dir

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, exit_on_failure = False):
        pass

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        pass

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):
        pass

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type,
        verbose = False,
        exit_on_failure = False):
        pass
