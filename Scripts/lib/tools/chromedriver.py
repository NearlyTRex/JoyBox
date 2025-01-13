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

# ChromeDriver tool
class ChromeDriver(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "ChromeDriver"

    # Get config
    def GetConfig(self):
        return {
            "ChromeDriver": {
                "program": {
                    "windows": "ChromeDriver/windows/chromedriver.exe",
                    "linux": "ChromeDriver/linux/chromedriver"
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
        if programs.ShouldProgramBeInstalled("ChromeDriver", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://googlechromelabs.github.io/chrome-for-testing/",
                webpage_base_url = "https://storage.googleapis.com/chrome-for-testing-public",
                starts_with = "https://storage.googleapis.com/chrome-for-testing-public",
                ends_with = "win64/chromedriver-win64.zip",
                search_file = "chromedriver.exe",
                install_name = "ChromeDriver",
                install_dir = programs.GetProgramInstallDir("ChromeDriver", "windows"),
                backups_dir = programs.GetProgramBackupDir("ChromeDriver", "windows"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ChromeDriver")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("ChromeDriver", "linux"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://googlechromelabs.github.io/chrome-for-testing/",
                webpage_base_url = "https://storage.googleapis.com/chrome-for-testing-public",
                starts_with = "https://storage.googleapis.com/chrome-for-testing-public",
                ends_with = "linux64/chromedriver-linux64.zip",
                search_file = "chromedriver",
                install_name = "ChromeDriver",
                install_dir = programs.GetProgramInstallDir("ChromeDriver", "linux"),
                backups_dir = programs.GetProgramBackupDir("ChromeDriver", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ChromeDriver")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("ChromeDriver", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ChromeDriver", "windows"),
                install_name = "ChromeDriver",
                install_dir = programs.GetProgramInstallDir("ChromeDriver", "windows"),
                search_file = "chromedriver.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ChromeDriver")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("ChromeDriver", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("ChromeDriver", "linux"),
                install_name = "ChromeDriver",
                install_dir = programs.GetProgramInstallDir("ChromeDriver", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup ChromeDriver")
                return False
        return True
