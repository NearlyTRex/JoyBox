# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import programs
from joybox import archive
from joybox.nintendo import wii
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase

# Install every .wad under the dir into Dolphin's Wii NAND; False at the first failure
def install_package_dir(package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for wad_file in paths.build_file_list_by_extensions(package_dir, extensions = [".wad"]):
        success = wii.install_wii_wad(
            src_wad_file = wad_file,
            nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Dolphin", "setup_dir"), "Wii"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Unzip the locker's Wii archive into the platform's setup dir, keeping files
# already there; True when the locker has no such archive
def extract_system_archive(platform, obj, setup_params):
    if not os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval())):
        return True
    success = archive.extract_archive(
        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Dolphin"), obj + config.ArchiveFileType.ZIP.cval()),
        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("Dolphin", "setup_dir", platform), obj),
        skip_existing = True,
        verbose = setup_params.verbose,
        pretend_run = setup_params.pretend_run,
        exit_on_failure = setup_params.exit_on_failure)
    if not success:
        logger.log_error("Could not extract Dolphin system files")
        return False
    return True

# Dolphin emulator
class Dolphin(emulatorbase.EmulatorBase):

    NAME = "Dolphin"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        dlc_dirs = [] if dlc_dirs is None else dlc_dirs
        update_dirs = [] if update_dirs is None else update_dirs
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                if not install_package_dir(package_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
                    return False
        return True

    # Write its config files, verify the locker system files, then unzip the Wii archive
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
                logger.log_error("Could not setup Dolphin config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["Wii"]:
                if not extract_system_archive(platform, obj, setup_params):
                    return False
        return True

    # Run Dolphin on the game file, turning on its fullscreen display option when asked
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
            programs.get_emulator_program("Dolphin"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--config", "Dolphin.Display.Fullscreen=True"
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
