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
                    "windows": "Wad2Bin/windows/wad2bin-windows-x64.exe",
                    "linux": "Wad2Bin/linux/wad2bin"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Wad2Bin", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "DarkMatterCore",
                github_repo = "wad2bin",
                starts_with = "wad2bin-windows-x64",
                ends_with = ".exe",
                search_file = "wad2bin-windows-x64.exe",
                install_name = "Wad2Bin",
                install_dir = programs.GetProgramInstallDir("Wad2Bin", "windows"),
                backups_dir = programs.GetProgramBackupDir("Wad2Bin", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Wad2Bin")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("Wad2Bin", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "DarkMatterCore",
                github_repo = "wad2bin",
                starts_with = "wad2bin-linux-x86_64",
                ends_with = ".tar.gz",
                search_file = "wad2bin",
                install_name = "Wad2Bin",
                install_dir = programs.GetProgramInstallDir("Wad2Bin", "linux"),
                backups_dir = programs.GetProgramBackupDir("Wad2Bin", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Wad2Bin")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Wad2Bin", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Wad2Bin", "windows"),
                install_name = "Wad2Bin",
                install_dir = programs.GetProgramInstallDir("Wad2Bin", "windows"),
                search_file = "wad2bin-windows-x64.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Wad2Bin")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Wad2Bin", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Wad2Bin", "linux"),
                install_name = "Wad2Bin",
                install_dir = programs.GetProgramInstallDir("Wad2Bin", "linux"),
                search_file = "wad2bin",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Wad2Bin")
                return False
        return True
