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

# HeroicGogDL tool
class HeroicGogDL(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "HeroicGogDL"

    # Get config
    def GetConfig(self):
        return {
            "HeroicGogDL": {
                "program": "HeroicGogDL/lib/main.py",
                "login_script": "HeroicGogDL/lib/login.py",
                "auth_json": "HeroicGogDL/lib/auth.json"
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download library
        if programs.ShouldLibraryBeInstalled("HeroicGogDL"):
            success = network.DownloadGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HeroicGogDL",
                output_dir = programs.GetLibraryInstallDir("HeroicGogDL", "lib"),
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HeroicGogDL")
                return False
            success = network.ArchiveGithubRepository(
                github_user = "NearlyTRex",
                github_repo = "HeroicGogDL",
                output_dir = programs.GetLibraryBackupDir("HeroicGogDL", "lib"),
                recursive = True,
                clean = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HeroicGogDL")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup library
        if programs.ShouldLibraryBeInstalled("HeroicGogDL"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetLibraryBackupDir("HeroicGogDL", "lib"),
                install_name = "HeroicGogDL",
                install_dir = programs.GetLibraryInstallDir("HeroicGogDL", "lib"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup HeroicGogDL")
                return False
        return True
