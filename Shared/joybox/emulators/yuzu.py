# Local imports
from joybox import config
from joybox import environment
from joybox import filebulk
from joybox import logger
from joybox import programs
from joybox.nintendo import switch
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase

# Install every .nsp under the dir into Yuzu's NAND; False at the first failure
def install_package_dir(package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for nsp_file in paths.build_file_list_by_extensions(package_dir, extensions = [".nsp"]):
        success = switch.install_switch_nsp(
            nsp_file = nsp_file,
            nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Yuzu", "setup_dir"), "nand"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Write each platform's profiles file for the configured user; False, after logging, at the first failure
def create_profiles(setup_params):
    for platform in ["windows", "linux"]:
        success = switch.create_switch_profiles_dat(
            profiles_file = programs.get_emulator_path_config_value("Yuzu", "profiles_file", platform),
            user_id = programs.get_emulator_config_value("Yuzu", "profile_user_id"),
            account_name = programs.get_emulator_config_value("Yuzu", "profile_account_name"),
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not setup Yuzu profiles")
            return False
    return True

# Yuzu emulator
class Yuzu(emulatorbase.EmulatorBase):

    NAME = "Yuzu"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        return emulatorcommon.install_package_dirs(
            install_package_dir,
            dlc_dirs = dlc_dirs,
            update_dirs = update_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Write its config files, write each platform's profiles file for the configured user,
    # then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
            return False

        # Create profiles
        if not create_profiles(setup_params):
            return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Yuzu"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Yuzu", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Yuzu system files")
                    return False
        return True

    # Run Yuzu with -g on the game file, with -f when fullscreen is asked
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
            programs.get_emulator_program("Yuzu"),
            "-g", config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
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
