# Imports
import os, os.path
import sys

# Local imports
import config
import system
import network
import programs
import environment
import toolbase

# Config file
config_files = {}
config_files["AppImageTool/linux/app.desktop"] = """
[Desktop Entry]
Type=Application
Name=App
Icon=icon
Categories=Game;
"""

# AppImageTool tool
class AppImageTool(toolbase.ToolBase):

    # Get name
    def GetName(self):
        return "AppImageTool"

    # Get config
    def GetConfig(self):
        return {
            "AppImageTool": {
                "program": {
                    "windows": None,
                    "linux": "AppImageTool/linux/AppImageTool.AppImage"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download linux program
        if programs.ShouldProgramBeInstalled("AppImageTool", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "AppImage",
                github_repo = "AppImageKit",
                starts_with = "appimagetool-x86_64",
                ends_with = ".AppImage",
                search_file = "AppImageTool.AppImage",
                install_name = "AppImageTool",
                install_dir = programs.GetProgramInstallDir("AppImageTool", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Download icons
        network.DownloadLatestGithubSource(
            github_user = "NearlyTRex",
            github_repo = "BostonIcons",
            output_dir = os.path.join(programs.GetProgramInstallDir("AppImageTool", "linux"), "BostonIcons"),
            clean_first = True,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetToolsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Copy icon
        system.CopyFileOrDirectory(
            src = os.path.join(programs.GetProgramInstallDir("AppImageTool", "linux"), "BostonIcons", "128", "mimes", "application-x-executable-script.svg"),
            dest = os.path.join(programs.GetProgramInstallDir("AppImageTool", "linux"), "icon.svg"),
            verbose = verbose,
            exit_on_failure = exit_on_failure)
