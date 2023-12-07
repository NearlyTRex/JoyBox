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

# Xemu emulator
class Xemu(base.EmulatorBase):

    # Get name
    def GetName():
        return "Xemu"

    # Get platforms
    def GetPlatforms():
        return config.xemu_platforms

    # Get config
    def GetConfig():
        return {
            "Xemu": {
                "program": {
                    "windows": "Xemu/windows/xemu.exe",
                    "linux": "Xemu/linux/Xemu.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "Xemu/windows",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu"
                },
                "config_file": {
                    "windows": "Xemu/windows/xemu.toml",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Xemu", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mborgerson",
                github_repo = "xemu",
                starts_with = "xemu",
                ends_with = "win-release.zip",
                search_file = "xemu.exe",
                install_name = "Xemu",
                install_dir = programs.GetProgramInstallDir("Xemu", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Xemu", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/mborgerson/xemu.git",
                output_name = "Xemu",
                output_dir = programs.GetProgramInstallDir("Xemu", "linux"),
                build_cmd = [
                    "./build.sh"
                ],
                internal_copies = [
                    {"from": "Source/dist/xemu", "to": "AppImage/usr/bin/xemu"},
                    {"from": "Source/ui/xemu.desktop", "to": "AppImage/xemu.desktop"},
                    {"from": "Source/ui/icons/xemu.svg", "to": "AppImage/xemu.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xemu", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Xemu"),
            dest = programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Xemu"),
            dest = programs.GetEmulatorPathConfigValue("Xemu", "setup_dir", "windows"),
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
            programs.GetEmulatorProgram("Xemu"),
            "-dvd_path", config.token_game_file
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
