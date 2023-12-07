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

# DXVK library
class DXVK(base.ThirdPartyLibraryBase):

    # Get name
    def GetName():
        return "DXVK"

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldThirdPartyLibraryBeInstalled("DXVK"):
            network.DownloadLatestGithubRelease(
                github_user = "doitsujin",
                github_repo = "dxvk",
                starts_with = "dxvk-2.2",
                ends_with = ".tar.gz",
                search_file = "x64/d3d9.dll",
                install_name = "DXVK",
                install_dir = programs.GetThirdPartyLibraryInstallDir("DXVK"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
