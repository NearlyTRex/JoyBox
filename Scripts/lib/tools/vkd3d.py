# Imports
import os, os.path
import sys

# Local imports
import config
import release
import system
import programs
import environment
import toolbase

# Config files
config_files = {}

# Get libs
def GetLibs(key):
    lib_files = []
    lib_root = programs.GetLibraryInstallDir("VKD3D", "lib")
    for potential_file in system.BuildFileList(lib_root):
        for lib_file in programs.GetToolConfigValue("VKD3D", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def GetLibs32():
    return GetLibs("lib32")

# Get 64-bit libs
def GetLibs64():
    return GetLibs("lib64")

# VKD3D tool
class VKD3D(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "VKD3D"

    # Get config
    def GetConfig(self):
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download library
        if programs.ShouldLibraryBeInstalled("VKD3D"):
            success = release.DownloadGithubRelease(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton",
                ends_with = ".tar.zst",
                install_name = "VKD3D-Proton",
                install_dir = programs.GetLibraryInstallDir("VKD3D", "lib"),
                backups_dir = programs.GetLibraryBackupDir("VKD3D", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup VKD3D")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup library
        if programs.ShouldLibraryBeInstalled("VKD3D"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("VKD3D", "lib"),
                install_name = "VKD3D",
                install_dir = programs.GetLibraryInstallDir("VKD3D", "lib"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup VKD3D")
                return False
        return True
