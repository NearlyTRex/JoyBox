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
config_files["Sunshine/windows/config/sunshine.conf"] = ""
config_files["Sunshine/linux/Sunshine.AppImage.home/.config/sunshine/sunshine.conf"] = ""

# Sunshine tool
class Sunshine(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "Sunshine"

    # Get config
    def GetConfig(self):
        return {
            "Sunshine": {
                "program": {
                    "windows": "Sunshine/windows/sunshine.exe",
                    "linux": "Sunshine/linux/Sunshine.AppImage"
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
        if programs.ShouldProgramBeInstalled("Sunshine", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = "windows.zip",
                search_file = "sunshine.exe",
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "windows"),
                backups_dir = programs.GetProgramBackupDir("Sunshine", "windows"),
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Sunshine", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "LizardByte",
                github_repo = "Sunshine",
                starts_with = "sunshine",
                ends_with = ".AppImage",
                search_file = "Sunshine.AppImage",
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "linux"),
                backups_dir = programs.GetProgramBackupDir("Sunshine", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Sunshine", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Sunshine", "windows"),
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "windows"),
                search_file = "sunshine.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Sunshine", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Sunshine", "linux"),
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine config files")
