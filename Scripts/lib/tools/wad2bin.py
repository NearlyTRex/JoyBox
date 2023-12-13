# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# Wad2Bin tool
class Wad2Bin(toolbase.ToolBase):

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
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
