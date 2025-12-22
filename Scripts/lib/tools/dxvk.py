# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import release
import programs
import toolbase

# Config files
config_files = {}

# Get libs
def get_libs(key):
    lib_files = []
    lib_root = programs.get_library_install_dir("DXVK", "lib")
    for potential_file in paths.build_file_list(lib_root):
        for lib_file in programs.get_tool_config_value("DXVK", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def get_libs32():
    return get_libs("lib32")

# Get 64-bit libs
def get_libs64():
    return get_libs("lib64")

# DXVK tool
class DXVK(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "DXVK"

    # Get config
    def get_config(self):
        return {
            "DXVK": {
                "lib32": [
                    "x32/d3d10core.dll",
                    "x32/d3d11.dll",
                    "x32/d3d9.dll",
                    "x32/dxgi.dll"
                ],
                "lib64": [
                    "x64/d3d10core.dll",
                    "x64/d3d11.dll",
                    "x64/d3d9.dll",
                    "x64/dxgi.dll"
                ]
            }
        }

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.should_library_be_installed("DXVK"):
            success = release.download_github_release(
                github_user = "doitsujin",
                github_repo = "dxvk",
                starts_with = "dxvk-2.2",
                ends_with = ".tar.gz",
                install_name = "DXVK",
                install_dir = programs.get_library_install_dir("DXVK", "lib"),
                backups_dir = programs.get_library_backup_dir("DXVK", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DXVK")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.should_library_be_installed("DXVK"):
            success = release.setup_stored_release(
                archive_dir = programs.get_library_backup_dir("DXVK", "lib"),
                install_name = "DXVK",
                install_dir = programs.get_library_install_dir("DXVK", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup DXVK")
                return False
        return True
