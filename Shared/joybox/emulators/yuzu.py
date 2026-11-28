# Local imports
from joybox import config
from joybox import logger
from joybox import programs
from joybox.nintendo import switch
from joybox import paths
from joybox import emulatorbase


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

    # Install every .nsp under the dir into Yuzu's NAND; False at the first failure
    def install_package_dir(self, package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
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

        return self.install_system_files(setup_params)
