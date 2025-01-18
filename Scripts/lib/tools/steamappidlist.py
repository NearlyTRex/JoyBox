# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import toolbase

# Config files
config_files = {}

# SteamAppIDList tool
class SteamAppIDList(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "SteamAppIDList"

    # Get config
    def GetConfig(self):
        return {
            "SteamAppIDList": {
                "csv": "SteamAppIDList/lib/steamcmd_appid.csv"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("SteamAppIDList"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "SteamAppIDList",
                output_dir = programs.GetLibraryInstallDir("SteamAppIDList", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup SteamAppIDList")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "SteamAppIDList",
                output_dir = programs.GetLibraryBackupDir("SteamAppIDList", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup SteamAppIDList")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("SteamAppIDList"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("SteamAppIDList", "lib"),
                install_name = "SteamAppIDList",
                install_dir = programs.GetLibraryInstallDir("SteamAppIDList", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup SteamAppIDList")
                return False
        return True
