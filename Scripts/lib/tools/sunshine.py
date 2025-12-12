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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Sunshine")
                return False

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
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Sunshine")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Sunshine", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Sunshine", "windows"),
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "windows"),
                search_file = "sunshine.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Sunshine")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Sunshine", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Sunshine", "linux"),
                install_name = "Sunshine",
                install_dir = programs.GetProgramInstallDir("Sunshine", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Sunshine")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup Sunshine config files")
                return False
        return True
