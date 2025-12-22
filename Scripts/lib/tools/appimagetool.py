# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
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
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

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
                backups_dir = programs.GetProgramBackupDir("AppImageTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup linux program
        if programs.ShouldProgramBeInstalled("AppImageTool", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("AppImageTool", "linux"),
                install_name = "AppImageTool",
                install_dir = programs.GetProgramInstallDir("AppImageTool", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup AppImageTool")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Copy icon
        if environment.IsLinuxPlatform():
            success = system.CopyFileOrDirectory(
                src = system.JoinPaths(environment.GetScriptsIconsDir(), "BostonIcons", "128", "mimes", "application-x-executable-script.svg"),
                dest = system.JoinPaths(programs.GetProgramInstallDir("AppImageTool", "linux"), "icon.svg"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not copy AppImageTool icons")
                return False

        # Create config files
        if environment.IsLinuxPlatform():
            for config_filename, config_contents in config_files.items():
                success = system.TouchFile(
                    src = system.JoinPaths(environment.GetToolsRootDir(), config_filename),
                    contents = config_contents.strip(),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not create AppImageTool config files")
                    return False
        return True
