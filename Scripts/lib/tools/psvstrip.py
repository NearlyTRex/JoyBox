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

# PSVStrip tool
class PSVStrip(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "PSVStrip"

    # Get config
    def GetConfig(self):
        return {
            "PSVStrip": {
                "program": {
                    "windows": "PSVStrip/windows/psvstrip.exe",
                    "linux": "PSVStrip/windows/psvstrip.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("PSVStrip", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Kippykip",
                github_repo = "PSVStrip",
                starts_with = "PSVStrip",
                ends_with = ".zip",
                search_file = "psvstrip.exe",
                install_name = "PSVStrip",
                install_dir = programs.GetProgramInstallDir("PSVStrip", "windows"),
                backups_dir = programs.GetProgramBackupDir("PSVStrip", "windows"),
                install_files = ["psvstrip.exe"],
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup PSVStrip")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("PSVStrip", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("PSVStrip", "windows"),
                install_name = "PSVStrip",
                install_dir = programs.GetProgramInstallDir("PSVStrip", "windows"),
                search_file = "psvstrip.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup PSVStrip")
                return False
        return True
