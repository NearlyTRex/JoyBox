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
import archive
import nintendo
import launchcommon
import gui

# Local imports
from . import base

# Config files
config_files = {}
config_files["Yuzu/windows/user/config/qt-config.ini"] = """
[Data%20Storage]
dump_directory="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/dump"
load_directory="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/load"
nand_directory="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/nand"
sdmc_directory="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/sdmc"
tas_directory="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/tas"

[UI]
Screenshots\screenshot_path="$EMULATOR_MAIN_ROOT/Yuzu/windows/user/screenshots"
"""
config_files["Yuzu/linux/Yuzu.AppImage.home/.config/yuzu/qt-config.ini"] = """
[Data%20Storage]
dump_directory="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/dump"
load_directory="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/load"
nand_directory="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand"
sdmc_directory="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/sdmc"
tas_directory="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/tas"

[UI]
Screenshots\screenshot_path="$EMULATOR_MAIN_ROOT/Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/screenshots"
"""

# Yuzu emulator
class Yuzu(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Yuzu"

    # Get platforms
    def GetPlatforms(self):
        return config.yuzu_platforms

    # Get config
    def GetConfig(self):
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
                "profiles_file": {
                    "windows": "Yuzu/windows/user/nand/system/save/8000000000000010/su/avators/profiles.dat",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand/system/save/8000000000000010/su/avators/profiles.dat"
                },
                "profile_user_id": "F6F389D41D6BC0BDD6BD928C526AE556",
                "profile_account_name": "yuzu",
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
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

        # Create profiles
        for platform in ["windows", "linux"]:
            nintendo.CreateSwitchProfilesDat(
                profiles_file = programs.GetEmulatorPathConfigValue("Yuzu", "profiles_file", platform),
                user_id = programs.GetEmulatorConfigValue("Yuzu", "profile_user_id"),
                account_name = programs.GetEmulatorConfigValue("Yuzu", "profile_account_name"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("Yuzu"),
                dest = programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", platform),
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
            launch_capture_type = launch_capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
