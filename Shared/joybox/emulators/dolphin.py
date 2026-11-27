# Imports

# Local imports
from joybox import config
from joybox import programs
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

# Dolphin emulator
class Dolphin(emulatorbase.EmulatorBase):

    NAME = "Dolphin"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        return emulatorcommon.install_package_dirs(
            install_package_dir,
            dlc_dirs = dlc_dirs,
            update_dirs = update_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Write its config files, verify the locker system files, then unzip the Wii archive
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
            for obj in ["Wii"]:
                if not self.extract_system_archive(platform, obj, setup_params):
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
