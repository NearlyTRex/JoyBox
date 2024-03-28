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

# Get 32-bit libs
def GetLibs32():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("VKD3D", "lib32"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("VKD3D"), lib_file))
    return lib_files

# Get 64-bit libs
def GetLibs64():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("VKD3D", "lib64"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("VKD3D"), lib_file))
    return lib_files

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
                    "windows/vkd3d-proton-2.12/x86/d3d12.dll",
                    "windows/vkd3d-proton-2.12/x86/d3d12core.dll"
                ],
                "lib64": [
                    "windows/vkd3d-proton-2.12/x64/d3d12.dll",
                    "windows/vkd3d-proton-2.12/x64/d3d12core.dll"
                ]
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows library
        if programs.ShouldLibraryBeInstalled("VKD3D"):
            success = release.DownloadGithubRelease(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton-2.12",
                ends_with = ".tar.zst",
                install_name = "VKD3D-Proton",
                install_dir = programs.GetLibraryInstallDir("VKD3D", "windows"),
                backups_dir = programs.GetLibraryBackupDir("VKD3D", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup VKD3D")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows library
        if programs.ShouldLibraryBeInstalled("VKD3D"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("VKD3D", "windows"),
                install_name = "VKD3D",
                install_dir = programs.GetLibraryInstallDir("VKD3D", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup VKD3D")
