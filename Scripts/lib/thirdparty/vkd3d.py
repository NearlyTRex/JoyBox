# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import network
import programs

# Local imports
from . import base

# VKD3D library
class VKD3D(base.ThirdPartyLibraryBase):

    # Get name
    def GetName(self):
        return "VKD3D"

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldThirdPartyLibraryBeInstalled("VKD3D"):
            network.DownloadLatestGithubRelease(
                github_user = "HansKristian-Work",
                github_repo = "vkd3d-proton",
                starts_with = "vkd3d-proton",
                ends_with = ".tar.zst",
                search_file = "x64/d3d12.dll",
                install_name = "VKD3D-Proton",
                install_dir = programs.GetThirdPartyLibraryInstallDir("VKD3D"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
