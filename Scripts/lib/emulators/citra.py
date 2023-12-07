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

# Citra emulator
class Citra(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Citra"

    # Get platforms
    def GetPlatforms(self):
        return config.citra_platforms

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
    def Download(self, force_downloads = False):
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
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
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
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        for obj in ["nand", "sysdata"]:
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "linux"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "linux"), obj),
                    skip_existing = True,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "windows"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Citra"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Citra", "setup_dir", "windows"), obj),
                    skip_existing = True,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

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
            launch_capture_type = launch_capture_type)
