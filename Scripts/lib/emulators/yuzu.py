# Imports
import os
import os.path
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

# Yuzu emulator
class Yuzu(base.EmulatorBase):

    # Get name
    def GetName():
        return "Yuzu"

    # Get platforms
    def GetPlatforms():
        return config.yuzu_platforms

    # Get config
    def GetConfig():
        return {
            "Yuzu": {
                "program": {
                    "windows": "Yuzu/windows/yuzu.exe",
                    "linux": "Yuzu/linux/Yuzu.AppImage"
                },
                "save_dir": {
                    "windows": "Yuzu/windows/user/nand/user/save/0000000000000000/F6F389D41D6BC0BDD6BD928C526AE556",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand/user/save/0000000000000000/F6F389D41D6BC0BDD6BD928C526AE556"
                },
                "setup_dir": {
                    "windows": "Yuzu/windows/user",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu"
                },
                "config_file": {
                    "windows": "Yuzu/windows/user/config/qt-config.ini",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.config/yuzu/qt-config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Yuzu", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "yuzu-emu",
                github_repo = "yuzu-mainline",
                starts_with = "yuzu-windows-msvc",
                ends_with = ".7z",
                search_file = "yuzu.exe",
                install_name = "Yuzu",
                install_dir = programs.GetProgramInstallDir("Yuzu", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Yuzu", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "yuzu-emu",
                github_repo = "yuzu-mainline",
                starts_with = "yuzu-mainline",
                ends_with = ".AppImage",
                search_file = "Yuzu.AppImage",
                install_name = "Yuzu",
                install_dir = programs.GetProgramInstallDir("Yuzu", "linux"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Yuzu"),
            dest = programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Yuzu"),
            dest = programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", "windows"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Launch
    def Launch(
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Yuzu"),
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
            launch_capture_type = launch_capture_type)
