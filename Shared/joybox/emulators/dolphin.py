# Imports

# Local imports
from joybox import programs
from joybox.nintendo import wii
from joybox import paths
from joybox import emulatorbase


# Dolphin emulator
class Dolphin(emulatorbase.EmulatorBase):

    NAME = "Dolphin"

    SYSTEM_ARCHIVES = ("Wii",)

    # Install every .wad under the dir into Dolphin's Wii NAND; False at the first failure
    def install_package_dir(self, package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
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
