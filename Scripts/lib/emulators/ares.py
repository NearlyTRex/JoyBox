# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import release
import programs
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
Paths
  Home
  Saves: EMULATOR_SETUP_ROOT/Saves/
  Screenshots: EMULATOR_SETUP_ROOT/Screenshots/
ColecoVision
  Path
  Firmware
    BIOS.World: EMULATOR_SETUP_ROOT/Bios/colecovision.rom
PCEngineCD
  Path
  Firmware
    BIOS.US: EMULATOR_SETUP_ROOT/Bios/syscard3u.pce
    BIOS.Japan: EMULATOR_SETUP_ROOT/Bios/syscard3j.pce
MegaCD
  Path
  Firmware
    BIOS.US: EMULATOR_SETUP_ROOT/Bios/bios_CD_U.bin
    BIOS.Japan: EMULATOR_SETUP_ROOT/Bios/bios_CD_J.bin
    BIOS.Europe: EMULATOR_SETUP_ROOT/Bios/bios_CD_E.bin
Hotkey
  ToggleFullscreen: 0x1/0/0;;
VirtualPad1
  Pad.Up: 0x3/1/1/Lo;;
  Pad.Down: 0x3/1/1/Hi;;
  Pad.Left: 0x3/1/0/Lo;;
  Pad.Right: 0x3/1/0/Hi;;
  Select: 0x3/3/6;;
  Start: 0x3/3/7;;
  A..South: 0x3/3/0;;
  B..East: 0x3/3/1;;
  X..West: 0x3/3/2;;
  Y..North: 0x3/3/3;;
  L-Bumper: 0x3/3/4;;
  R-Bumper: 0x3/3/5;;
  L-Trigger: 0x3/0/2/Hi;;
  R-Trigger: 0x3/0/5/Hi;;
  L-Stick..Click: 0x3/3/9;;
  R-Stick..Click: 0x3/3/10;;
  L-Up: 0x3/0/1/Lo;;
  L-Down: 0x3/0/1/Hi;;
  L-Left: 0x3/0/0/Lo;;
  L-Right: 0x3/0/0/Hi;;
  R-Up: 0x3/0/4/Lo;;
  R-Down: 0x3/0/4/Hi;;
  R-Left: 0x3/0/3/Lo;;
  R-Right: 0x3/0/3/Hi;;
"""
config_files["Ares/windows/settings.bml"] = config_file_general
config_files["Ares/linux/Ares.AppImage.home/.local/share/ares/settings.bml"] = config_file_general

# System files
system_files = {}
system_files["Bios/bios_CD_E.bin"] = "e66fa1dc5820d254611fdcdba0662372"
system_files["Bios/bios_CD_J.bin"] = "278a9397d192149e84e820ac621a8edd"
system_files["Bios/bios_CD_U.bin"] = "2efd74e3232ff260e371b99f84024f7f"
system_files["Bios/colecovision.rom"] = "2c66f5911e5b42b8ebe113403548eee7"
system_files["Bios/syscard3j.pce"] = "38179df8f4ac870017db21ebcbf53114"
system_files["Bios/syscard3u.pce"] = "0754f903b52e3b3342202bdafb13efa5"

# Ares emulator
class Ares(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Ares"

    # Get platforms
    def GetPlatforms(self):
        return [

            # Microsoft
            config.Platform.MICROSOFT_MSX,

            # Nintendo
            config.Platform.NINTENDO_64,
            config.Platform.NINTENDO_FAMICOM,
            config.Platform.NINTENDO_NES,
            config.Platform.NINTENDO_SNES,
            config.Platform.NINTENDO_SNES_MSU1,
            config.Platform.NINTENDO_SUPER_FAMICOM,

            # Other
            config.Platform.OTHER_ATARI_2600,
            config.Platform.OTHER_BANDAI_WONDERSWAN_COLOR,
            config.Platform.OTHER_BANDAI_WONDERSWAN,
            config.Platform.OTHER_COLECO_COLECOVISION,
            config.Platform.OTHER_NEC_PCENGINE,
            config.Platform.OTHER_NEC_PCENGINE_CD,
            config.Platform.OTHER_NEC_SUPERGRAFX,
            config.Platform.OTHER_NEC_TURBOGRAFX_16,
            config.Platform.OTHER_NEC_TURBOGRAFX_CD,
            config.Platform.OTHER_SEGA_32X,
            config.Platform.OTHER_SEGA_CD_32X,
            config.Platform.OTHER_SEGA_CD,
            config.Platform.OTHER_SEGA_GAME_GEAR,
            config.Platform.OTHER_SEGA_GENESIS,
            config.Platform.OTHER_SEGA_MASTER_SYSTEM,
            config.Platform.OTHER_SINCLAIR_ZX_SPECTRUM,
            config.Platform.OTHER_SNK_NEOGEO_POCKET_COLOR
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
                    config.Platform.MICROSOFT_MSX: "MSX",

                    # Nintendo
                    config.Platform.NINTENDO_64: "Nintendo 64",
                    config.Platform.NINTENDO_FAMICOM: "Famicom",
                    config.Platform.NINTENDO_NES: "Famicom",
                    config.Platform.NINTENDO_SNES: "Super Famicom",
                    config.Platform.NINTENDO_SNES_MSU1: "Super Famicom",
                    config.Platform.NINTENDO_SUPER_FAMICOM: "Super Famicom",

                    # Other
                    config.Platform.OTHER_ATARI_2600: "Atari 2600",
                    config.Platform.OTHER_BANDAI_WONDERSWAN: "WonderSwan",
                    config.Platform.OTHER_BANDAI_WONDERSWAN_COLOR: "WonderSwan Color",
                    config.Platform.OTHER_COLECO_COLECOVISION: "ColecoVision",
                    config.Platform.OTHER_NEC_PCENGINE: "PC Engine",
                    config.Platform.OTHER_NEC_PCENGINE_CD: "PC Engine CD",
                    config.Platform.OTHER_NEC_SUPERGRAFX: "SuperGrafx",
                    config.Platform.OTHER_NEC_TURBOGRAFX_16: "PC Engine",
                    config.Platform.OTHER_NEC_TURBOGRAFX_CD: "PC Engine CD",
                    config.Platform.OTHER_SEGA_32X: "Mega 32X",
                    config.Platform.OTHER_SEGA_CD: "Mega CD",
                    config.Platform.OTHER_SEGA_CD_32X: "Mega CD 32X",
                    config.Platform.OTHER_SEGA_GAME_GEAR: "Game Gear",
                    config.Platform.OTHER_SEGA_GENESIS: "Mega Drive",
                    config.Platform.OTHER_SEGA_MASTER_SYSTEM: "Master System",
                    config.Platform.OTHER_SINCLAIR_ZX_SPECTRUM: "ZX Spectrum",
                    config.Platform.OTHER_SNK_NEOGEO_POCKET_COLOR: "Neo Geo Pocket Color"
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

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Ares", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "ares-emulator",
                github_repo = "ares",
                starts_with = "ares",
                ends_with = "windows.zip",
                search_file = "ares.exe",
                install_name = "Ares",
                install_dir = programs.GetProgramInstallDir("Ares", "windows"),
                backups_dir = programs.GetProgramBackupDir("Ares", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ares")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("Ares", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Ares.git",
                output_file = "ares-x86_64.AppImage",
                install_name = "Ares",
                install_dir = programs.GetProgramInstallDir("Ares", "linux"),
                backups_dir = programs.GetProgramBackupDir("Ares", "linux"),
                build_cmd = [
                    "make", "-j4", "build=release"
                ],
                internal_copies = [
                    {"from": "Source/desktop-ui/out/ares", "to": "AppImage/usr/bin/ares"},
                    {"from": "Source/desktop-ui/resource/ares.desktop", "to": "AppImage/ares.desktop"},
                    {"from": "Source/desktop-ui/resource/ares.png", "to": "AppImage/ares.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/ares", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/mia/Database", "to": "Ares.AppImage.home/.local/share/ares/Database"},
                    {"from": "Source/mia/Firmware", "to": "Ares.AppImage.home/.local/share/ares/Firmware"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ares")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Ares", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ares", "windows"),
                install_name = "Ares",
                install_dir = programs.GetProgramInstallDir("Ares", "windows"),
                search_file = "ares.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ares")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Ares", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Ares", "linux"),
                install_name = "Ares",
                install_dir = programs.GetProgramInstallDir("Ares", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ares")
                return False
        return True

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Ares config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Ares"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Ares system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Ares"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("Ares", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Could not setup Ares system files")
                    return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get game info
        game_platform = game_info.get_platform()

        # Get system types
        system_types = programs.GetEmulatorConfigValue("Ares", "save_sub_dirs")

        # Check if this platform is valid
        if not game_platform in system_types:
            gui.DisplayErrorPopup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in Ares config" % game_platform)

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("Ares"),
            "--system",
            system_types[game_platform],
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen"
            ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
