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

# Wad2Bin tool
class Wad2Bin(base.ToolBase):

    # Get name
    def GetName(self):
        return "Wad2Bin"

    # Get config
    def GetConfig(self):
        return {
            "Wad2Bin": {
                "program": {
                    "windows": "Wad2Bin/windows/wad2bin.exe",
                    "linux": "Wad2Bin/windows/wad2bin.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Wad2Bin", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "DarkMatterCore",
                github_repo = "wad2bin",
                starts_with = "wad2bin",
                ends_with = ".exe",
                search_file = "wad2bin.exe",
                install_name = "Wad2Bin",
                install_dir = programs.GetProgramInstallDir("Wad2Bin", "windows"),
                install_files = ["wad2bin.exe"],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
