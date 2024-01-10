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

# Get 32-bit libs
def GetLibs32():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("DXVK", "lib32"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("DXVK"), lib_file))
    return lib_files

# Get 64-bit libs
def GetLibs64():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("DXVK", "lib64"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("DXVK"), lib_file))
    return lib_files

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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("DXVK"):
            success = release.DownloadLatestGithubRelease(
                github_user = "doitsujin",
                github_repo = "dxvk",
                starts_with = "dxvk-2.2",
                ends_with = ".tar.gz",
                search_file = "x64/d3d9.dll",
                install_name = "DXVK",
                install_dir = programs.GetLibraryInstallDir("DXVK"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup DXVK")
