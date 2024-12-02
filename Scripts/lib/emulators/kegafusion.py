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

# KegaFusion emulator
class KegaFusion(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "KegaFusion"

    # Get platforms
    def GetPlatforms(self):
        return []

    # Get config
    def GetConfig(self):
        return {
            "KegaFusion": {
                "program": {
                    "windows": "KegaFusion/windows/Fusion.exe",
                    "linux": "KegaFusion/windows/Fusion.exe"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": True
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("KegaFusion", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://retrocdn.net/images/6/6c/Fusion364.7z",
                search_file = "Fusion.exe",
                install_name = "KegaFusion",
                install_dir = programs.GetProgramInstallDir("KegaFusion", "windows"),
                backups_dir = programs.GetProgramBackupDir("KegaFusion", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup KegaFusion")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("KegaFusion", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("KegaFusion", "windows"),
                install_name = "KegaFusion",
                install_dir = programs.GetProgramInstallDir("KegaFusion", "windows"),
                search_file = "Fusion.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup KegaFusion")
