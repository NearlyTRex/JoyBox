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

# Ares emulator
class Ares(base.EmulatorBase):

    # Get name
    def GetName():
        return "Ares"

    # Get platforms
    def GetPlatforms():
        return config.ares_platforms

    # Get config
    def GetConfig():
        return {
            "Ares": {
                "program": {
                    "windows": "Ares/windows/ares.exe",
                    "linux": "Ares/linux/Ares.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "save_base_dir": {
                    "windows": "Ares/windows/Saves",
                    "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares/Saves"
                },
                "save_sub_dirs": {

                    # Microsoft
                    "Microsoft MSX": "MSX",

                    # Nintendo
                    "Nintendo 64": "Nintendo 64",
                    "Nintendo Famicom": "Famicom",
                    "Nintendo NES": "Famicom",
                    "Nintendo SNES": "Super Famicom",
                    "Nintendo Super Famicom": "Super Famicom",

                    # Other
                    "Atari 2600": "Atari 2600",
                    "Bandai WonderSwan": "WonderSwan",
                    "Bandai WonderSwan Color": "WonderSwan Color",
                    "Coleco ColecoVision": "ColecoVision",
                    "NEC SuperGrafx": "SuperGrafx",
                    "NEC TurboGrafx CD & PC-Engine CD": "PC Engine CD",
                    "NEC TurboGrafx-16 & PC-Engine": "PC Engine",
                    "Sega 32X": "Mega 32X",
                    "Sega CD": "Mega CD",
                    "Sega CD 32X": "Mega CD 32X",
                    "Sega Game Gear": "Game Gear",
                    "Sega Genesis": "Mega Drive",
                    "Sega Master System": "Master System",
                    "Sinclair ZX Spectrum": "ZX Spectrum",
                    "SNK Neo Geo Pocket Color": "Neo Geo Pocket Color"
                },
                "setup_dir": {
                    "windows": "Ares/windows",
                    "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares"
                },
                "config_file": {
                    "windows": "Ares/windows/settings.bml",
                    "linux": "Ares/linux/Ares.AppImage.home/.local/share/ares/settings.bml"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Ares", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "ares-emulator",
                github_repo = "ares",
                starts_with = "ares",
                ends_with = "windows.zip",
                search_file = "ares.exe",
                install_name = "Ares",
                install_dir = programs.GetProgramInstallDir("Ares", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Ares", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/ares-emulator/ares.git",
                output_name = "Ares",
                output_dir = programs.GetProgramInstallDir("Ares", "linux"),
                build_cmd = [
                    "make", "-j4", "build=release"
                ],
                internal_copies = [
                    {"from": "Source/desktop-ui/out/ares", "to": "AppImage/usr/bin/ares"},
                    {"from": "Source/desktop-ui/resource/ares.desktop", "to": "AppImage/ares.desktop"},
                    {"from": "Source/desktop-ui/resource/ares.png", "to": "AppImage/ares.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/ares", "to": "AppRun"}
                ],
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Ares"),
            dest = programs.GetEmulatorPathConfigValue("Ares", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = environment.GetSyncedGameEmulatorSetupDir("Ares"),
            dest = programs.GetEmulatorPathConfigValue("Ares", "setup_dir", "windows"),
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

        # Get system types
        system_types = programs.GetEmulatorConfigValue("Ares", "save_sub_dirs")

        # Check if this platform is valid
        if not launch_platform in system_types:
            gui.DisplayErrorPopup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in Ares config" % launch_platform)

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Ares"),
            "--system",
            system_types[launch_platform],
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
