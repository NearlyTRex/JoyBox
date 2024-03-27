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
    def Setup(self, verbose = False, exit_on_failure = False):

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
                install_files = ["sunshine.exe", "assets", "scripts", "tools"],
                release_type = config.release_type_archive,
                verbose = verbose,
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
                release_type = config.release_type_program,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Sunshine config files")
