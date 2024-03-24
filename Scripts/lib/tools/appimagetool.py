# Imports
import os, os.path
import sys

# Local imports
import config
import system
import release
import programs
import environment
import toolbase

# Config files
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
            success = release.DownloadGithubRelease(
                github_user = "AppImage",
                github_repo = "AppImageKit",
                starts_with = "appimagetool-x86_64",
                ends_with = ".AppImage",
                search_file = "AppImageTool.AppImage",
                install_name = "AppImageTool",
                install_dir = programs.GetProgramInstallDir("AppImageTool", "linux"),
                release_type = config.release_type_program,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup AppImageTool")

        # Copy icon
        if environment.IsLinuxPlatform():
            success = system.CopyFileOrDirectory(
                src = os.path.join(programs.GetLibraryInstallDir("AppIcons"), "128", "mimes", "application-x-executable-script.svg"),
                dest = os.path.join(programs.GetProgramInstallDir("AppImageTool", "linux"), "icon.svg"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not copy AppImageTool icons")

        # Create config files
        if environment.IsLinuxPlatform():
            for config_filename, config_contents in config_files.items():
                success = system.TouchFile(
                    src = os.path.join(environment.GetToolsRootDir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not create AppImageTool config files")
