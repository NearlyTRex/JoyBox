# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import release
import programs
import toolbase

# Config files
config_files = {}
config_files["RClone/windows/rclone.conf"] = ""
config_files["RClone/linux/rclone.conf"] = ""

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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("RClone", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-windows-amd64.zip",
                search_file = "rclone.exe",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "windows"),
                backups_dir = programs.GetProgramBackupDir("RClone", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RClone")

        # Download linux program
        if programs.ShouldProgramBeInstalled("RClone", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://downloads.rclone.org/rclone-current-linux-amd64.zip",
                search_file = "rclone",
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "linux"),
                backups_dir = programs.GetProgramBackupDir("RClone", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RClone")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("RClone", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RClone", "windows"),
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "windows"),
                search_file = "rclone.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RClone")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("RClone", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RClone", "linux"),
                install_name = "RClone",
                install_dir = programs.GetProgramInstallDir("RClone", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RClone")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RClone config files")
