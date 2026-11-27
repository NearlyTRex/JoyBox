# Imports

# Local imports
from joybox import config
from joybox import filebulk
from joybox import paths
from joybox import emulatorbase

# Copy the .rap and .edat files from the game's cache dir into its save exdata dir
def copy_exdata_files(game_cache_dir, game_save_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for exdata_file in paths.build_file_list_by_extensions(game_cache_dir, extensions = [".rap", ".edat"]):
        filebulk.smart_copy(
            src = exdata_file,
            dest = paths.join_paths(game_save_dir, "exdata"),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# RPCS3 emulator
class RPCS3(emulatorbase.EmulatorBase):

    NAME = "RPCS3"

    # Write its config files, verify the locker system files, then unzip the dev_flash archive
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
            for obj in ["dev_flash"]:
                if not self.extract_system_archive(platform, obj, setup_params):
                    return False
        return True

    # Copy a PSN game's .rap and .edat files into its save dir before RPCS3 runs; a failed copy
    # doesn't stop the launch
    def prepare_launch(self, game_info, verbose = False, pretend_run = False, exit_on_failure = False):
        if game_info.get_platform() == config.Platform.SONY_PLAYSTATION_NETWORK_PS3:
            copy_exdata_files(game_info.get_local_cache_dir(), game_info.get_save_dir(), verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        return True
