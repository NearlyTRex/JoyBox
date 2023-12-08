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

# Config files
config_files = {}
config_files["mGBA/windows/portable.ini"] = ""
config_files["mGBA/windows/config.ini"] = """
[ports.qt]
gb.bios=$EMULATOR_MAIN_ROOT/mGBA/windows/bios/gb_bios.bin
gbc.bios=$EMULATOR_MAIN_ROOT/mGBA/windows/bios/gbc_bios.bin
gba.bios=$EMULATOR_MAIN_ROOT/mGBA/windows/bios/gba_bios.bin
sgb.bios=$EMULATOR_MAIN_ROOT/mGBA/windows/bios/sgb_bios.bin
savegamePath=$GAME_SAVE_DIR
"""
config_files["mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"] = """
[ports.qt]
gb.bios=$EMULATOR_MAIN_ROOT/mGBA/linux/mGBA.AppImage.home/.config/mgba/bios/gb_bios.bin
gbc.bios=$EMULATOR_MAIN_ROOT/mGBA/linux/mGBA.AppImage.home/.config/mgba/bios/gbc_bios.bin
gba.bios=$EMULATOR_MAIN_ROOT/mGBA/linux/mGBA.AppImage.home/.config/mgba/bios/gba_bios.bin
sgb.bios=$EMULATOR_MAIN_ROOT/mGBA/linux/mGBA.AppImage.home/.config/mgba/bios/sgb_bios.bin
savegamePath=$GAME_SAVE_DIR
"""

# MGBA emulator
class MGBA(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "mGBA"

    # Get platforms
    def GetPlatforms(self):
        return config.mgba_platforms

    # Get config
    def GetConfig(self):
        return {
            "mGBA": {
                "program": {
                    "windows": "mGBA/windows/mGBA.exe",
                    "linux": "mGBA/linux/mGBA.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "mGBA/windows",
                    "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba"
                },
                "config_file": {
                    "windows": "mGBA/windows/config.ini",
                    "linux": "mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("mGBA", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = "win64.7z",
                search_file = "mGBA.exe",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("mGBA", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = ".appimage",
                search_file = "mGBA.AppImage",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "linux"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("mGBA"),
            dest = programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("mGBA"),
            dest = programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", "windows"),
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
            programs.GetEmulatorProgram("mGBA"),
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
