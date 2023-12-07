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

# MelonDS emulator
class MelonDS(base.EmulatorBase):

    # Get name
    def GetName():
        return "melonDS"

    # Get platforms
    def GetPlatforms():
        return config.melonds_platforms

    # Get config
    def GetConfig():
        return {
            "melonDS": {
                "program": {
                    "windows": "melonDS/windows/melonDS.exe",
                    "linux": "melonDS/linux/melonDS.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "melonDS/windows",
                    "linux": "melonDS/linux/melonDS.AppImage.home/.config/melonDS"
                },
                "config_file": {
                    "windows": "melonDS/windows/melonDS.ini",
                    "linux": "melonDS/linux/melonDS.AppImage.home/.config/melonDS/melonDS.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("melonDS", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "melonDS-emu",
                github_repo = "melonDS",
                starts_with = "melonDS",
                ends_with = "win_x64.zip",
                search_file = "melonDS.exe",
                install_name = "melonDS",
                install_dir = programs.GetProgramInstallDir("melonDS", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("melonDS", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/melonDS-emu/melonDS.git",
                output_name = "melonDS",
                output_dir = programs.GetProgramInstallDir("melonDS", "linux"),
                build_cmd = [
                    "cmake", "..", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/melonDS", "to": "AppImage/usr/bin/melonDS"},
                    {"from": "Source/res/net.kuribo64.melonDS.desktop", "to": "AppImage/net.kuribo64.melonDS.desktop"},
                    {"from": "Source/res/icon/melon_256x256.png", "to": "AppImage/net.kuribo64.melonDS.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/melonDS", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
            dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
            dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", "windows"),
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
            programs.GetEmulatorProgram("melonDS"),
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
