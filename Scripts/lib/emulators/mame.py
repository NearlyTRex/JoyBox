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

# Mame emulator
class Mame(base.EmulatorBase):

    # Get name
    def GetName():
        return "Mame"

    # Get platforms
    def GetPlatforms():
        return config.mame_platforms

    # Get config
    def GetConfig():
        return {
            "Mame": {
                "program": {
                    "windows": "Mame/windows/mame.exe",
                    "linux": "Mame/linux/Mame.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "Mame/windows",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame"
                },
                "config_dir": {
                    "windows": "Mame/windows",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame"
                },
                "config_file": {
                    "windows": "Mame/windows/mame.ini",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame/mame.ini"
                },
                "roms_dir": {
                    "windows": "Mame/windows/roms",
                    "linux": "Mame/linux/Mame.AppImage.home/.mame/roms"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Mame", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "mamedev",
                github_repo = "mame",
                starts_with = "mame",
                ends_with = "64bit.exe",
                search_file = "mame.exe",
                install_name = "Mame",
                install_dir = programs.GetProgramInstallDir("Mame", "windows"),
                installer_type = config.installer_format_7zip,
                is_installer = False,
                is_archive = True,
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Mame", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/mamedev/mame.git",
                output_name = "Mame",
                output_dir = programs.GetProgramInstallDir("Mame", "linux"),
                build_cmd = [
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/mame", "to": "AppImage/usr/bin/mame"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.png", "to": "AppImage/icon.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mame", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/uismall.bdf", "to": "Mame.AppImage.home/.mame/uismall.bdf"},
                    {"from": "Source/artwork", "to": "Mame.AppImage.home/.mame/artwork"},
                    {"from": "Source/bgfx", "to": "Mame.AppImage.home/.mame/bgfx"},
                    {"from": "Source/ctrlr", "to": "Mame.AppImage.home/.mame/ctrlr"},
                    {"from": "Source/docs", "to": "Mame.AppImage.home/.mame/docs"},
                    {"from": "Source/hash", "to": "Mame.AppImage.home/.mame/hash"},
                    {"from": "Source/hlsl", "to": "Mame.AppImage.home/.mame/hlsl"},
                    {"from": "Source/ini", "to": "Mame.AppImage.home/.mame/ini"},
                    {"from": "Source/language", "to": "Mame.AppImage.home/.mame/language"},
                    {"from": "Source/plugins", "to": "Mame.AppImage.home/.mame/plugins"},
                    {"from": "Source/roms", "to": "Mame.AppImage.home/.mame/roms"},
                    {"from": "Source/samples", "to": "Mame.AppImage.home/.mame/samples"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Mame"),
            dest = programs.GetEmulatorPathConfigValue("Mame", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Mame"),
            dest = programs.GetEmulatorPathConfigValue("Mame", "setup_dir", "windows"),
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
        launch_cmd = [programs.GetEmulatorProgram("Mame")]

        # Add ini path
        launch_cmd += [
            "-inipath", programs.GetEmulatorPathConfigValue("Mame", "config_dir")
        ]

        # Add rom path
        if launch_platform == "Arcade":
            launch_cmd += [
                "-rompath", config.token_game_dir
            ]
        else:
            launch_cmd += [
                "-rompath", programs.GetEmulatorPathConfigValue("Mame", "roms_dir")
            ]

        # Add launch file
        if launch_platform == "Arcade":
            launch_cmd += [
                config.token_game_name
            ]
        elif launch_platform == "Atari 5200":
            launch_cmd += [
                "a5200",
                "-cart", config.token_game_file
            ]
        elif launch_platform == "Atari 7800":
            launch_cmd += [
                "a7800",
                "-cart", config.token_game_file
            ]
        elif launch_platform == "Magnavox Odyssey 2":
            launch_cmd += [
                "odyssey2",
                "-cart", config.token_game_file
            ]
        elif launch_platform == "Mattel Intellivision":
            launch_cmd += [
                "intv",
                "-cart", config.token_game_file
            ]
        elif launch_platform == "Philips CDi":
            launch_cmd += [
                "cdimono1",
                "-cdrom", config.token_game_file
            ]
        elif launch_platform == "Texas Instruments TI-99-4A":
            launch_cmd += [
                "ti99_4a",
                "-cart", config.token_game_file
            ]
        elif launch_platform == "Tiger Game.com":
            launch_cmd += [
                "gamecom",
                "-cart1", config.token_game_file
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