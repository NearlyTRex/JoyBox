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
    for lib_file in programs.GetToolConfigValue("GoldbergEmu", "lib32"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("GoldbergEmu"), lib_file))
    return lib_files

# Get 64-bit libs
def GetLibs64():
    lib_files = []
    for lib_file in programs.GetToolConfigValue("GoldbergEmu", "lib64"):
        lib_files.append(os.path.join(programs.GetLibraryInstallDir("GoldbergEmu"), lib_file))
    return lib_files

# GoldbergEmu tool
class GoldbergEmu(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "GoldbergEmu"

    # Get config
    def GetConfig(self):
        return {
            "GoldbergEmu": {
                "lib32": [
                    "windows/steam_api.dll"
                ],
                "lib64": [
                    "windows/steam_api64.dll"
                ]
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows library
        if programs.ShouldLibraryBeInstalled("GoldbergEmu"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://gitlab.com/Mr_Goldberg/goldberg_emulator/-/jobs/4247811310/artifacts/download",
                install_name = "GoldbergEmu",
                install_dir = programs.GetLibraryInstallDir("GoldbergEmu", "windows"),
                backups_dir = programs.GetLibraryBackupDir("GoldbergEmu", "windows"),
                release_type = config.release_type_archive,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GoldbergEmu")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows library
        if programs.ShouldLibraryBeInstalled("GoldbergEmu"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("GoldbergEmu", "windows"),
                install_name = "GoldbergEmu",
                install_dir = programs.GetLibraryInstallDir("GoldbergEmu", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GoldbergEmu")
