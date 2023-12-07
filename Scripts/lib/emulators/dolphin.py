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

# Dolphin emulator
class Dolphin(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Dolphin"

    # Get platforms
    def GetPlatforms(self):
        return config.dolphin_platforms

    # Get config
    def GetConfig(self):
        return {
            "Dolphin": {
                "program": {
                    "windows": "Dolphin/windows/Dolphin.exe",
                    "linux": "Dolphin/linux/Dolphin.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "save_base_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
                },
                "save_sub_dirs": {

                    # Nintendo
                    "Nintendo Gamecube": "GC",
                    "Nintendo Wii": "Wii/title/00010000"
                },
                "setup_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
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
        if force_downloads or programs.ShouldProgramBeInstalled("Dolphin", "windows"):
            network.DownloadLatestWebpageRelease(
                webpage_url = "https://dolphin-emu.org/download/",
                starts_with = "https://dl.dolphin-emu.org/builds",
                ends_with = "x64.7z",
                search_file = "Dolphin.exe",
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Dolphin", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/dolphin-emu/dolphin.git",
                output_name = "Dolphin",
                output_dir = programs.GetProgramInstallDir("Dolphin", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Binaries/dolphin-emu", "to": "AppImage/usr/bin/dolphin-emu"},
                    {"from": "Source/Build/Binaries/dolphin-tool", "to": "AppImage/usr/bin/dolphin-tool"},
                    {"from": "Source/Data/Sys", "to": "AppImage/usr/bin/Sys"},
                    {"from": "Source/Data/dolphin-emu.desktop", "to": "AppImage/dolphin-emu.desktop"},
                    {"from": "Source/Data/dolphin-emu.png", "to": "AppImage/dolphin-emu.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/dolphin-emu", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        for obj in ["Wii"]:
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "linux"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "linux"), obj),
                    skip_existing = True,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "windows"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", "windows"), obj),
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
            programs.GetEmulatorProgram("Dolphin"),
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
