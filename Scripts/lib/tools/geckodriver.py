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

# GeckoDriver tool
class GeckoDriver(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "GeckoDriver"

    # Get config
    def GetConfig(self):
        return {
            "GeckoDriver": {
                "program": {
                    "windows": "GeckoDriver/windows/geckodriver.exe",
                    "linux": "GeckoDriver/linux/geckodriver"
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
        if programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "win32.zip",
                search_file = "geckodriver.exe",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                backups_dir = programs.GetProgramBackupDir("GeckoDriver", "windows"),
                install_files = ["geckodriver.exe"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")

        # Download linux program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "mozilla",
                github_repo = "geckodriver",
                starts_with = "geckodriver",
                ends_with = "linux64.tar.gz",
                search_file = "geckodriver",
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                backups_dir = programs.GetProgramBackupDir("GeckoDriver", "linux"),
                install_files = ["geckodriver"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("GeckoDriver", "windows"),
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "windows"),
                search_file = "geckodriver.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("GeckoDriver", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("GeckoDriver", "linux"),
                install_name = "GeckoDriver",
                install_dir = programs.GetProgramInstallDir("GeckoDriver", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup GeckoDriver")
