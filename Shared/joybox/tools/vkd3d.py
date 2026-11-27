# Local imports
from joybox import config
from joybox import release
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import toolbase


# Files under the VKD3D lib dir whose names end with an entry of the given tool config list
def get_libs(key):
    lib_files = []
    lib_root = programs.get_library_install_dir("VKD3D", "lib")
    for potential_file in paths.build_file_list(lib_root):
        for lib_file in programs.get_tool_config_value("VKD3D", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def get_libs32():
    return get_libs("lib32")

# Get 64-bit libs
def get_libs64():
    return get_libs("lib64")

# VKD3D tool
class VKD3D(toolbase.ToolBase):

    NAME = "VKD3D"

    # Download the HansKristian-Work/vkd3d-proton release tarball into its lib dir
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("VKD3D"):
            success = release.download_github_release(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton",
                ends_with = ".tar.zst",
                install_name = "VKD3D-Proton",
                install_dir = programs.get_library_install_dir("VKD3D", "lib"),
                backups_dir = programs.get_library_backup_dir("VKD3D", "lib"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VKD3D")
                return False
        return True

    # Install the library from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("VKD3D"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("VKD3D", "lib"),
                install_name = "VKD3D",
                install_dir = programs.get_library_install_dir("VKD3D", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VKD3D")
                return False
        return True
