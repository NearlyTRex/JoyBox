# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import launchcommon
import gui
import emulatorbase

# Config files
config_files = {}
config_files["melonDS/windows/melonDS.ini"] = """
BIOS9Path=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/nds_arm9_usa.bin
BIOS7Path=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/nds_arm7_usa.bin
FirmwarePath=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/nds_firmware_usa.bin
DSiBIOS9Path=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/dsi_arm9_usa.bin
DSiBIOS7Path=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/dsi_arm7_usa.bin
DSiFirmwarePath=$EMULATOR_MAIN_ROOT/melonDS/windows/sysdata/dsi_firmware_usa.bin
DSiNANDPath=$EMULATOR_MAIN_ROOT/melonDS/windows/nand/dsi_nand_usa.bin
SaveFilePath=$GAME_SAVE_DIR
"""
config_files["melonDS/linux/melonDS.AppImage.home/.config/melonDS/melonDS.ini"] = """
BIOS9Path=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/nds_arm9_usa.bin
BIOS7Path=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/nds_arm7_usa.bin
FirmwarePath=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/nds_firmware_usa.bin
DSiBIOS9Path=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/dsi_arm9_usa.bin
DSiBIOS7Path=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/dsi_arm7_usa.bin
DSiFirmwarePath=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/sysdata/dsi_firmware_usa.bin
DSiNANDPath=$EMULATOR_MAIN_ROOT/melonDS/linux/melonDS.AppImage.home/.config/melonDS/nand/dsi_nand_usa.bin
SaveFilePath=$GAME_SAVE_DIR
"""

# MelonDS emulator
class MelonDS(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "melonDS"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_nintendo_ds,
            config.game_subcategory_nintendo_dsi
        ]

    # Get config
    def GetConfig(self):
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
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
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
                src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
                dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", platform),
                skip_existing = True,
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

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("melonDS"),
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
