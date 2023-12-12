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

# Config file
config_files = {}
config_files["Ares/windows/settings.bml"] = """
Paths
  Home
  Saves: $EMULATOR_MAIN_ROOT/Ares/windows/Saves/
  Screenshots: $EMULATOR_MAIN_ROOT/Ares/windows/Screenshots/
ColecoVision
  Path
  Firmware
    BIOS.World: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/colecovision.rom
PCEngineCD
  Path
  Firmware
    BIOS.US: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/syscard3u.pce
    BIOS.Japan: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/syscard3j.pce
MegaCD
  Path
  Firmware
    BIOS.US: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/bios_CD_U.bin
    BIOS.Japan: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/bios_CD_J.bin
    BIOS.Europe: $EMULATOR_MAIN_ROOT/Ares/windows/Bios/bios_CD_E.bin
"""
config_files["Ares/linux/Ares.AppImage.home/.local/share/ares/settings.bml"] = """
Paths
  Home
  Saves: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Saves/
  Screenshots: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Screenshots/
ColecoVision
  Path
  Firmware
    BIOS.World: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/colecovision.rom
PCEngineCD
  Path
  Firmware
    BIOS.US: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/syscard3u.pce
    BIOS.Japan: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/syscard3j.pce
MegaCD
  Path
  Firmware
    BIOS.US: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/bios_CD_U.bin
    BIOS.Japan: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/bios_CD_J.bin
    BIOS.Europe: $EMULATOR_MAIN_ROOT/Ares/linux/Ares.AppImage.home/.local/share/ares/Bios/bios_CD_E.bin
"""

# Ares emulator
class Ares(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Ares"

    # Get platforms
    def GetPlatforms(self):
        return [

            # Microsoft
            "Microsoft MSX",

            # Nintendo
            "Nintendo 64",
            "Nintendo Famicom",
            "Nintendo NES",
            "Nintendo SNES",
            "Nintendo Super Famicom",

            # Other
            "Atari 2600",
            "Bandai WonderSwan Color",
            "Bandai WonderSwan",
            "Coleco ColecoVision",
            "NEC SuperGrafx",
            "NEC TurboGrafx CD & PC-Engine CD",
            "NEC TurboGrafx-16 & PC-Engine",
            "Sega 32X",
            "Sega CD 32X",
            "Sega CD",
            "Sega Game Gear",
            "Sega Genesis",
            "Sega Master System",
            "Sinclair ZX Spectrum",
            "SNK Neo Geo Pocket Color"
        ]

    # Get config
    def GetConfig(self):
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
                "setup_files": [
                    {
                        "file": "Bios/bios_CD_E.bin",
                        "md5": "e66fa1dc5820d254611fdcdba0662372"
                    },
                    {
                        "file": "Bios/bios_CD_J.bin",
                        "md5": "278a9397d192149e84e820ac621a8edd"
                    },
                    {
                        "file": "Bios/bios_CD_U.bin",
                        "md5": "2efd74e3232ff260e371b99f84024f7f"
                    },
                    {
                        "file": "Bios/colecovision.rom",
                        "md5": "2c66f5911e5b42b8ebe113403548eee7"
                    },
                    {
                        "file": "Bios/syscard3j.pce",
                        "md5": "38179df8f4ac870017db21ebcbf53114"
                    },
                    {
                        "file": "Bios/syscard3u.pce",
                        "md5": "0754f903b52e3b3342202bdafb13efa5"
                    }
                ],
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
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
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

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("Ares"),
                dest = programs.GetEmulatorPathConfigValue("Ares", "setup_dir", platform),
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
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

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
        if fullscreen:
            launch_cmd += [
                "--fullscreen"
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
