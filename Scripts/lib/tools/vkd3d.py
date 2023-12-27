# Imports
import os, os.path
import sys

# Local imports
import config
import network
import system
import programs
import environment
import toolbase

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
                    "vkd3d-proton/x86/d3d12.dll",
                    "vkd3d-proton/x86/d3d12core.dll"
                ],
                "lib64": [
                    "vkd3d-proton/x64/d3d12.dll",
                    "vkd3d-proton/x64/d3d12core.dll"
                ]
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("VKD3D"):
            success = network.DownloadLatestGithubRelease(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton",
                ends_with = ".tar.zst",
                search_file = "x64/d3d12.dll",
                install_name = "VKD3D-Proton",
                install_dir = programs.GetLibraryInstallDir("VKD3D"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup VKD3D")

        # Find first dll file
        dll_files = system.BuildFileListByExtensions(programs.GetLibraryInstallDir("VKD3D"), extensions = [".dll"])
        dll_file = None
        if len(dll_files):
            dll_file = dll_files.pop()

        # Rename path
        if dll_file:
            dll_dir_old = system.GetDirectoryParent(system.GetFilenameDirectory(dll_file))
            dll_dir_new = os.path.join(programs.GetLibraryInstallDir("VKD3D"), "vkd3d-proton")
            success = system.MoveFileOrDirectory(
                src = dll_dir_old,
                dest = dll_dir_new,
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup VKD3D path")
