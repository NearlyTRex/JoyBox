# Imports
import re
from abc import ABC

# Local imports
from joybox import archive
from joybox import config
from joybox import emulatorcommon
from joybox import filebulk
from joybox import gui
from joybox import fileops
from joybox import programcatalog
from joybox import programsetup
from joybox import programs
from joybox import environment
from joybox import paths
from joybox import hashutil
from joybox import logger
from joybox import platform_info

# The game placeholders an emulator's [launch] data can use, and the launch tokens they become
LAUNCH_TOKENS = {
    "{game_file}": config.TOKEN_GAME_FILE,
    "{game_dir}": config.TOKEN_GAME_DIR,
    "{game_name}": config.TOKEN_GAME_NAME,
}

# A launch argument that is the value a config table maps the game's platform to
PLATFORM_CONFIG_VALUE = re.compile(r"^\{platform_config:([A-Za-z0-9_]+)\}$")

# Base emulator
class EmulatorBase(ABC):

    # The name the emulator is registered under, which also files its program data
    NAME = ""

    # Folders whose locker zip archives configure unzips into each platform's setup dir;
    # when empty, configure copies the system files in as they are
    SYSTEM_ARCHIVES = ()

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

    # Install the packages in one DLC or update dir; the base has none to install
    def install_package_dir(self, package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
        del package_dir, verbose, pretend_run, exit_on_failure
        return True

    # Install each DLC dir, then each update dir, by install_package_dir; False at the first failure
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        return emulatorcommon.install_package_dirs(
            self.install_package_dir,
            dlc_dirs = dlc_dirs,
            update_dirs = update_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Download the emulator's releases for each platform it installs on, keeping backups,
    # by the [[setup]] steps in its program data
    def setup(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_EMULATORS, self.get_name(), setup_params = setup_params)

    # Install the emulator from its stored backup releases instead of downloading,
    # by the [[setup_offline]] steps in its program data
    def setup_offline(self, setup_params = None):
        return programsetup.run_setup_steps(programcatalog.FAMILY_EMULATORS, self.get_name(), offline = True, setup_params = setup_params)

    # Write its config files, then verify the locker system files and copy or unzip them
    # into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()
        if not self.write_config_files(setup_params):
            return False
        return self.install_system_files(setup_params)

    # Verify the locker system files, then unzip the SYSTEM_ARCHIVES into each platform's
    # setup dir, or copy the files there when it names none
    def install_system_files(self, setup_params):
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False
        if self.SYSTEM_ARCHIVES:
            return self.extract_system_archives(setup_params)
        return self.copy_system_files(setup_params)

    # Copy each locker system file into each platform's setup dir; False at the first failure
    def copy_system_files(self, setup_params):
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir(self.get_name()), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value(self.get_name(), "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup %s system files" % self.get_name())
                    return False
        return True

    # Unzip each of the SYSTEM_ARCHIVES into each platform's setup dir; False at the first failure
    def extract_system_archives(self, setup_params):
        for platform in ["windows", "linux"]:
            for obj in self.SYSTEM_ARCHIVES:
                if not self.extract_system_archive(platform, obj, setup_params):
                    return False
        return True

    # Write each config file the emulator lists under the emulators root, logging the
    # failure under label (its name by default); False at the first that fails
    def write_config_files(self, setup_params = None, label = None):
        if not setup_params:
            setup_params = config.SetupParams()
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup %s config files" % (label or self.get_name()))
                return False
        return True

    # Unzip the locker's archive of a system folder into the platform's setup dir, keeping
    # files already there; True when the locker has no such archive
    def extract_system_archive(self, platform, obj, setup_params):
        archive_file = paths.join_paths(
            environment.get_locker_gaming_emulator_setup_dir(self.get_name()),
            obj + config.ArchiveFileType.ZIP.cval())
        if not paths.does_path_exist(archive_file):
            return True
        success = archive.extract_archive(
            archive_file = archive_file,
            extract_dir = paths.join_paths(programs.get_emulator_path_config_value(self.get_name(), "setup_dir", platform), obj),
            skip_existing = True,
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not extract %s system files" % self.get_name())
            return False
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

    # Work a launch needs done before its command runs; True when it needs none
    def prepare_launch(self, game_info, verbose = False, pretend_run = False, exit_on_failure = False):
        del game_info, verbose, pretend_run, exit_on_failure
        return True

    # Values for the emulator's own {name} launch placeholders, beyond the game ones; none by default
    def get_launch_values(self, game_info):
        del game_info
        return {}

    # The value its config table maps the game's platform to; quits with an error popup when
    # the table has no entry for the platform
    def get_platform_config_value(self, key, game_platform):
        values = programs.get_emulator_config_value(self.get_name(), key)
        if game_platform not in values:
            gui.display_error_popup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in %s config" % (game_platform, self.get_name()))
        return values[game_platform]

    # One launch argument with its placeholder filled in from the values or the game's platform
    def fill_launch_argument(self, argument, values, game_info):
        if argument in values:
            return values[argument]
        match = PLATFORM_CONFIG_VALUE.match(argument)
        if match:
            return self.get_platform_config_value(match[1], game_info.get_platform())
        return argument

    # The program and its [launch] args for the game, with fullscreen_args for a fullscreen launch;
    # None when its data has no launch table
    def get_launch_command(self, game_info, fullscreen = False):
        launch = programcatalog.get_launch(programcatalog.FAMILY_EMULATORS, self.get_name())
        if not launch:
            return None
        values = {**LAUNCH_TOKENS, **{"{%s}" % key: value for key, value in self.get_launch_values(game_info).items()}}
        arguments = launch.get("args", []) + (launch.get("fullscreen_args", []) if fullscreen else [])
        return [programs.get_emulator_program(self.get_name())] + [self.fill_launch_argument(argument, values, game_info) for argument in arguments]

    # Start a game with the command from its launch data, after any work the launch needs,
    # optionally capturing video or a screenshot; False when it has no launch data
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):
        if not self.prepare_launch(game_info, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
            return False
        launch_cmd = self.get_launch_command(game_info, fullscreen = fullscreen)
        if not launch_cmd:
            return False
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
