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

# PPSSPP emulator
class PPSSPP(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "PPSSPP"

    # Get platforms
    def GetPlatforms(self):
        return config.ppsspp_platforms

    # Get config
    def GetConfig(self):
        return {
            "PPSSPP": {
                "program": {
                    "windows": "PPSSPP/windows/PPSSPPWindows64.exe",
                    "linux": "PPSSPP/linux/PPSSPP.AppImage"
                },
                "save_dir": {
                    "windows": "PPSSPP/windows/memstick/PSP/SAVEDATA",
                    "linux": "PPSSPP/linux/PPSSPP.AppImage.home/.config/ppsspp/PSP/SAVEDATA"
                },
                "config_file": {
                    "windows": None,
                    "linux": None
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("PPSSPP", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://www.ppsspp.org/files/1_16_6/ppsspp_win.zip",
                search_file = "PPSSPPWindows64.exe",
                install_name = "PPSSPP",
                install_dir = programs.GetProgramInstallDir("PPSSPP", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("PPSSPP", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/hrydgard/ppsspp.git",
                output_name = "PPSSPP",
                output_dir = programs.GetProgramInstallDir("PPSSPP", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/PPSSPPSDL", "to": "AppImage/usr/bin/PPSSPPSDL"},
                    {"from": "Source/Build/assets", "to": "AppImage/usr/bin/assets"},
                    {"from": "Source/Build/ppsspp.desktop", "to": "AppImage/ppsspp.desktop"},
                    {"from": "Source/icons/icon-512.svg", "to": "AppImage/ppsspp.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/PPSSPPSDL", "to": "AppRun"}
                ],
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
            programs.GetEmulatorProgram("PPSSPP"),
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
