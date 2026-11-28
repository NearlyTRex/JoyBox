# Imports

# Local imports
from joybox import programs
from joybox.nintendo import threeds
from joybox import paths
from joybox import emulatorbase


# Citra emulator
class Citra(emulatorbase.EmulatorBase):

    NAME = "Citra"

    SYSTEM_ARCHIVES = ("nand", "sysdata")

    # Install every .cia under the dir into Citra's sdmc dir; False at the first failure
    def install_package_dir(self, package_dir, verbose = False, pretend_run = False, exit_on_failure = False):
        for cia_file in paths.build_file_list_by_extensions(package_dir, extensions = [".cia"]):
            success = threeds.install_3ds_cia(
                src_3ds_file = cia_file,
                sdmc_dir = paths.join_paths(programs.get_emulator_path_config_value("Citra", "setup_dir"), "sdmc"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
        return True
