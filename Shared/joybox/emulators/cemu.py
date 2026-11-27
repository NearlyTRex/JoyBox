# Local imports
from joybox import logger
from joybox import programs
from joybox.nintendo import wiiu
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase

# Install the NUS package of every title.tik under the dir into Cemu's mlc01 NAND; False at the first failure
def install_package_dir(package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for tik_file in paths.build_file_list_by_extensions(package_dir, extensions = [".tik"]):
        if not tik_file.endswith("title.tik"):
            continue
        tik_dir = paths.get_filename_directory(tik_file)
        success = wiiu.install_wiiu_nus_package(
            nus_package_dir = tik_dir,
            nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Cemu", "setup_dir"), "mlc01"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Merge every .key.txt in the game's cache dir into each platform's keys file; False at the first failure
def update_keys(game_cache_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for key_file in paths.build_file_list_by_extensions(game_cache_dir, extensions = [".txt"]):
        if not key_file.endswith(".key.txt"):
            continue
        for platform in ["windows", "linux"]:
            success = wiiu.update_wiiu_keys(
                src_key_file = key_file,
                dest_key_file = programs.get_emulator_path_config_value("Cemu", "keys_file", platform),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                logger.log_error("Could not update Cemu keys from %s" % key_file)
                return False
    return True

# Cemu emulator
class Cemu(emulatorbase.EmulatorBase):

    NAME = "Cemu"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        return emulatorcommon.install_package_dirs(
            install_package_dir,
            dlc_dirs = dlc_dirs,
            update_dirs = update_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Write its config files under the emulators root
    def configure(self, setup_params = None):
        return self.write_config_files(setup_params)

    # Merge the game's .key.txt files into each platform's keys file before Cemu runs
    def prepare_launch(self, game_info, verbose = False, pretend_run = False, exit_on_failure = False):
        return update_keys(game_info.get_local_cache_dir(), verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
