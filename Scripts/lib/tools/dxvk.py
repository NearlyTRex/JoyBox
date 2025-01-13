# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import toolbase

# Config files
config_files = {}

# Get libs
def GetLibs(key):
    lib_files = []
    lib_root = programs.GetLibraryInstallDir("DXVK", "lib")
    for potential_file in system.BuildFileList(lib_root):
        for lib_file in programs.GetToolConfigValue("DXVK", key):
            if potential_file.endswith(lib_file):
                lib_files.append(potential_file)
    return lib_files

# Get 32-bit libs
def GetLibs32():
    return GetLibs("lib32")

# Get 64-bit libs
def GetLibs64():
    return GetLibs("lib64")

# DXVK tool
class DXVK(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "DXVK"

    # Get config
    def GetConfig(self):
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
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("DXVK"):
            success = release.DownloadGithubRelease(
                github_user = "doitsujin",
                github_repo = "dxvk",
                starts_with = "dxvk-2.2",
                ends_with = ".tar.gz",
                install_name = "DXVK",
                install_dir = programs.GetLibraryInstallDir("DXVK", "lib"),
                backups_dir = programs.GetLibraryBackupDir("DXVK", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup DXVK")
				return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("DXVK"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("DXVK", "lib"),
                install_name = "DXVK",
                install_dir = programs.GetLibraryInstallDir("DXVK", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
				system.LogError("Could not setup DXVK")
				return False
        return True
