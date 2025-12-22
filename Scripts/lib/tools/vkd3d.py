# Imports
import os, os.path
import sys

# Local imports
import config
import release
import system
import logger
import paths
import programs
import environment
import toolbase

# Config files
config_files = {}

# Get libs
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

    # Get name
    def get_name(self):
        return "VKD3D"

    # Get config
    def get_config(self):
        return {
            "VKD3D": {
                "lib32": [
                    "x86/d3d12.dll",
                    "x86/d3d12core.dll"
                ],
                "lib64": [
                    "x64/d3d12.dll",
                    "x64/d3d12core.dll"
                ]
            }
        }

    # Setup
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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VKD3D")
                return False
        return True

    # Setup offline
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
