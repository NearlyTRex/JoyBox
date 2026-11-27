# Imports
from abc import ABC, abstractmethod

# Local imports
from joybox import programcatalog
from joybox import programs
from joybox import environment
from joybox import paths
from joybox import hashutil
from joybox import logger
from joybox import platform_info

# Base emulator
class EmulatorBase(ABC):

    # The name the emulator is registered under, which also files its program data
    NAME = ""

    # The emulator's registered name
    def get_name(self):
        return self.NAME

    # The platforms whose games it plays, as its program data lists them
    def get_platforms(self):
        return programcatalog.get_emulator_platforms(self.get_name())

    # Get config, from the emulator's program data
    def get_config(self):
        return programcatalog.get_emulator_config(self.get_name())

    # Get the files setup writes, by path, with their contents
    def get_config_files(self):
        return programcatalog.get_config_files(programcatalog.FAMILY_EMULATORS, self.get_name())

    # Get the system files setup checks, by path, with their md5
    def get_system_files(self):
        return programcatalog.get_system_files(programcatalog.FAMILY_EMULATORS, self.get_name())

    # Path of the emulator's own config file for the platform, from its program data under the emulators root
    def get_config_file(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "config_file",
            program_platform = emulator_platform)

    # Directory the emulator keeps its setup files in for the platform, under the emulators root
    def get_setup_dir(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "setup_dir",
            program_platform = emulator_platform)

    # The kind of save data the emulator keeps; None in the base, emulators override it
    def get_save_type(self):
        return None

    # Root the per-platform save sub directories hang off, from the program data; None when unset
    def get_save_base_dir(self, emulator_platform = None):
        return programs.get_path_config_value(
            program_config = self.get_config(),
            base_dir = environment.get_emulators_root_dir(),
            program_name = self.get_name(),
            program_key = "save_base_dir",
            program_platform = emulator_platform)

    # Map of game platform to save sub directory, from the program data; None when unset
    def get_save_sub_dirs(self, emulator_platform = None):
        return programs.get_config_value(
            program_config = self.get_config(),
            program_name = self.get_name(),
            program_key = "save_sub_dirs",
            program_platform = emulator_platform)

    # Where saves for a game platform go: the base dir plus that platform's sub dir when the
    # program data maps one, else the plain save_dir; emulator platform defaults to the current one
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
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        del dlc_dirs, update_dirs, verbose, pretend_run, exit_on_failure
        return True

    # Download the emulator's releases for each platform it installs on, keeping backups
    @abstractmethod
    def setup(self, setup_params = None):
        ...

    # Install the emulator from its stored backup releases instead of downloading
    @abstractmethod
    def setup_offline(self, setup_params = None):
        ...

    # Write the config files and copy in verified system files after install; the base does nothing
    def configure(self, setup_params = None):
        del setup_params
        return True

    # Verify locker system files against their expected md5s
    def verify_system_files(self, system_files, setup_params):
        setup_dir = environment.get_locker_gaming_emulator_setup_dir(self.get_name())
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashutil.calculate_file_md5(
                src = paths.join_paths(setup_dir, filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)

            # Pretend runs read nothing, so there is no hash to compare
            if not setup_params.pretend_run and expected_md5 != actual_md5:
                logger.log_error("Could not verify %s system file %s" % (self.get_name(), filename))
                return False
        return True

    # Start a game, optionally capturing video or a screenshot; the base launches nothing and returns False
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        del game_info, capture_type, capture_file, fullscreen, verbose, pretend_run, exit_on_failure
        return False
