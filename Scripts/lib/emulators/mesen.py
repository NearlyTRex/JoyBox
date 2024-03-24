# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import emulatorbase

# Config files
config_files = {}

# System files
system_files = {}

# Mesen emulator
class Mesen(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Mesen"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "Mesen": {
                "program": {
                    "windows": "Mesen/windows/Mesen.exe",
                    "linux": "Mesen/linux/Mesen.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Mesen", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://nightly.link/SourMesen/Mesen2/workflows/build/master/Mesen%20%28Windows%29.zip",
                search_file = "Mesen.exe",
                install_name = "Mesen",
                install_dir = programs.GetProgramInstallDir("Mesen", "windows"),
                backups_dir = programs.GetProgramBackupDir("Mesen", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mesen")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Mesen", "linux"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://nightly.link/SourMesen/Mesen2/workflows/build/master/Mesen%20(Linux%20x64%20-%20AppImage).zip",
                search_file = "Mesen.AppImage",
                install_name = "Mesen",
                install_dir = programs.GetProgramInstallDir("Mesen", "linux"),
                backups_dir = programs.GetProgramBackupDir("Mesen", "linux"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Mesen")
