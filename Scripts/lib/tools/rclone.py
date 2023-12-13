# Imports
import os, os.path
import sys

# Local imports
import config
import network
import programs
import toolbase

# RClone tool
class RClone(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "RClone"

    # Get config
    def GetConfig(self):
        return {
            "RClone": {
                "program": {
                    "windows": "RClone/windows/rclone.exe",
                    "linux": "RClone/linux/rclone"
                },
                "config_file": {
                    "windows": "RClone/windows/rclone.conf",
                    "linux": "RClone/linux/rclone.conf"
                },
                "cache_dir": {
                    "windows": "RClone/windows/cache",
                    "linux": "RClone/linux/cache"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("RClone", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
                search_file = "rclone.exe",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("RClone", "linux"):
            network.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
                search_file = "rclone",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
