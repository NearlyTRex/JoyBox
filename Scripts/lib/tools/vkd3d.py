# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import network
import system
import programs
import environment

# Local imports
from . import base

# Get 32-bit libs
def GetLibs32():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("VKD3D", "lib32"):
        lib_files.apend(os.path.join(programs.GetLibraryInstallDir("VKD3D"), lib_file))
    return lib_files

# Get 64-bit libs
def GetLibs32():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("VKD3D", "lib64"):
        lib_files.apend(os.path.join(programs.GetLibraryInstallDir("VKD3D"), lib_file))
    return lib_files

# VKD3D tool
class VKD3D(base.ToolBase):

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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldLibraryBeInstalled("VKD3D"):
            network.DownloadLatestGithubRelease(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton",
                ends_with = ".tar.zst",
                search_file = "x64/d3d12.dll",
                install_name = "VKD3D-Proton",
                install_dir = programs.GetLibraryInstallDir("VKD3D"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Find first dll file
        dll_files = system.BuildFileListByExtensions(programs.GetLibraryInstallDir("VKD3D"), extensions = [".dll"])
        dll_file = dll_files.pop()

        # Rename path
        dll_dir_old = system.GetDirectoryParent(system.GetFilenameDirectory(dll_file))
        dll_dir_new = os.path.join(programs.GetLibraryInstallDir("VKD3D"), "vkd3d-proton")
        system.MoveFileOrDirectory(
            src = dll_dir_old,
            dest = dll_dir_new,
            skip_existing = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
