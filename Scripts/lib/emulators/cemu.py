# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import environment
import system
import network
import programs
import launchcommon
import gui

# Local imports
from . import base

# Config files
config_files = {}
config_files["Cemu/windows/settings.xml"] = ""
config_files["Cemu/windows/keys.txt"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"] = ""

# Cemu emulator
class Cemu(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Cemu"

    # Get platforms
    def GetPlatforms(self):
        return config.cemu_platforms

    # Get config
    def GetConfig(self):
        return {
            "Cemu": {
                "program": {
                    "windows": "Cemu/windows/Cemu.exe",
                    "linux": "Cemu/linux/Cemu.AppImage"
                },
                "save_dir": {
                    "windows": "Cemu/windows/mlc01/usr/save/00050000",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/mlc01/usr/save/00050000"
                },
                "setup_dir": {
                    "windows": "Cemu/windows",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu"
                },
                "config_file": {
                    "windows": "Cemu/windows/settings.xml",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"
                },
                "keys_file": {
                    "windows": "Cemu/windows/keys.txt",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Cemu", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "cemu",
                ends_with = "windows-x64.zip",
                search_file = "Cemu.exe",
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Cemu", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "Cemu",
                ends_with = ".AppImage",
                search_file = "Cemu.AppImage",
                install_name = "Cemu",
                install_dir = programs.GetProgramInstallDir("Cemu", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("Cemu"),
                dest = programs.GetEmulatorPathConfigValue("Cemu", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type,
        verbose = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Cemu"),
            "-g", config.token_game_file
        ]

        # Launch game
        launchcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
