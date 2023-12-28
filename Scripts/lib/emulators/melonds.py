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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
BIOS9Path=$EMULATOR_SETUP_ROOT/sysdata/nds_arm9_usa.bin
BIOS7Path=$EMULATOR_SETUP_ROOT/sysdata/nds_arm7_usa.bin
FirmwarePath=$EMULATOR_SETUP_ROOT/sysdata/nds_firmware_usa.bin
DSiBIOS9Path=$EMULATOR_SETUP_ROOT/sysdata/dsi_arm9_usa.bin
DSiBIOS7Path=$EMULATOR_SETUP_ROOT/sysdata/dsi_arm7_usa.bin
DSiFirmwarePath=$EMULATOR_SETUP_ROOT/sysdata/dsi_firmware_usa.bin
DSiNANDPath=$EMULATOR_SETUP_ROOT/nand/dsi_nand_usa.bin
SaveFilePath=$GAME_SAVE_DIR
"""
config_files["melonDS/windows/melonDS.ini"] = config_file_general
config_files["melonDS/linux/melonDS.AppImage.home/.config/melonDS/melonDS.ini"] = config_file_general

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
                "setup_files": [
                    {
                        "file": "sysdata/nds_firmware_usa.bin",
                        "md5": "10ec0b038afe62b6edf5d098615c8039"
                    },
                    {
                        "file": "sysdata/dsi_arm7_usa.bin",
                        "md5": "559dae4ea78eb9d67702c56c1d791e81"
                    },
                    {
                        "file": "sysdata/dsi_arm9_usa.bin",
                        "md5": "87b665fce118f76251271c3732532777"
                    },
                    {
                        "file": "sysdata/nds_arm7_usa.bin",
                        "md5": "df692a80a5b1bc90728bc3dfc76cd948"
                    },
                    {
                        "file": "sysdata/dsi_firmware_usa.bin",
                        "md5": "74f23348012d7b3e1cc216c47192ffeb"
                    },
                    {
                        "file": "sysdata/nds_arm9_usa.bin",
                        "md5": "a392174eb3e572fed6447e956bde4b25"
                    },
                    {
                        "file": "nds_key_world.cfg",
                        "md5": "c65df953c21897b85ebc8eefbba3c22f"
                    },
                    {
                        "file": "nand/dsi_nand_usa.bin",
                        "md5": "d9c875ded95daed312016f5c77f84db1"
                    }
                ],
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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download program
        if programs.ShouldProgramBeInstalled("melonDS", "windows"):
            success = network.DownloadLatestGithubRelease(
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
            system.AssertCondition(success, "Could not setup melonDS")

        # Build program
        if programs.ShouldProgramBeInstalled("melonDS", "linux"):
            success = network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/melonDS.git",
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
            system.AssertCondition(success, "Could not setup melonDS")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup melonDS config files")

        # Copy setup files
        for platform in ["windows", "linux"]:
            success = system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("melonDS"),
                dest = programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", platform),
                skip_existing = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup melonDS system files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
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
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
