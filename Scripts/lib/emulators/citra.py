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
import archive
import launchcommon
import gui

# Local imports
from . import base

# Config files
config_files = {}
config_files["Citra/windows/user/config/qt-config.ini"] = """
[Data%20Storage]
nand_directory=$EMULATOR_MAIN_ROOT/Citra/windows/user/nand/
sdmc_directory=$EMULATOR_MAIN_ROOT/Citra/windows/user/sdmc/

[UI]
Paths\screenshotPath=$EMULATOR_MAIN_ROOT/Citra/windows/user/screenshots/
"""
config_files["Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"] = """
[Data%20Storage]
nand_directory=$EMULATOR_MAIN_ROOT/Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/nand/
sdmc_directory=$EMULATOR_MAIN_ROOT/Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/sdmc/

[UI]
Paths\screenshotPath=$EMULATOR_MAIN_ROOT/Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/screenshots/
"""

# Citra emulator
class Citra(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Citra"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Nintendo 3DS",
            "Nintendo 3DS Apps",
            "Nintendo 3DS eShop"
        ]

    # Get config
    def GetConfig(self):
        return {
            "Citra": {
                "program": {
                    "windows": "Citra/windows/citra-qt.exe",
                    "linux": "Citra/linux/citra-qt.AppImage"
                },
                "save_dir": {
                    "windows": "Citra/windows/user/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000"
                },
                "setup_dir": {
                    "windows": "Citra/windows/user",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu"
                },
                "config_file": {
                    "windows": "Citra/windows/user/config/qt-config.ini",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Citra", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "citra-emu",
                github_repo = "citra-nightly",
                starts_with = "citra-windows-msvc",
                ends_with = ".7z",
                search_file = "citra-qt.exe",
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Citra", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "citra-emu",
                github_repo = "citra-nightly",
                starts_with = "citra-linux-appimage",
                ends_with = ".tar.gz",
                search_file = "citra-qt.AppImage",
                install_name = "Citra",
                install_dir = programs.GetProgramInstallDir("Citra", "linux"),
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

        # Extract setup files
        for platform in ["windows", "linux"]:
            for obj in ["nand", "sysdata"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip")):
                    archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", platform), obj),
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
            programs.GetEmulatorProgram("Citra"),
            config.token_game_file
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
