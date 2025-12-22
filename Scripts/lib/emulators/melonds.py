# Imports
import os
import os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
import release
import programs
import hashing
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
BIOS9Path=EMULATOR_SETUP_ROOT/sysdata/nds_arm9_usa.bin
BIOS7Path=EMULATOR_SETUP_ROOT/sysdata/nds_arm7_usa.bin
FirmwarePath=EMULATOR_SETUP_ROOT/sysdata/nds_firmware_usa.bin
DSiBIOS9Path=EMULATOR_SETUP_ROOT/sysdata/dsi_arm9_usa.bin
DSiBIOS7Path=EMULATOR_SETUP_ROOT/sysdata/dsi_arm7_usa.bin
DSiFirmwarePath=EMULATOR_SETUP_ROOT/sysdata/dsi_firmware_usa.bin
DSiNANDPath=EMULATOR_SETUP_ROOT/nand/dsi_nand_usa.bin
SaveFilePath=GAME_SAVE_DIR
"""
config_files["melonDS/windows/melonDS.ini"] = config_file_general
config_files["melonDS/linux/melonDS.AppImage.home/.config/melonDS/melonDS.ini"] = config_file_general

# System files
system_files = {}
system_files["sysdata/nds_firmware_usa.bin"] = "10ec0b038afe62b6edf5d098615c8039"
system_files["sysdata/dsi_arm7_usa.bin"] = "559dae4ea78eb9d67702c56c1d791e81"
system_files["sysdata/dsi_arm9_usa.bin"] = "87b665fce118f76251271c3732532777"
system_files["sysdata/nds_arm7_usa.bin"] = "df692a80a5b1bc90728bc3dfc76cd948"
system_files["sysdata/dsi_firmware_usa.bin"] = "74f23348012d7b3e1cc216c47192ffeb"
system_files["sysdata/nds_arm9_usa.bin"] = "a392174eb3e572fed6447e956bde4b25"
system_files["nds_key_world.cfg"] = "c65df953c21897b85ebc8eefbba3c22f"
system_files["nand/dsi_nand_usa.bin"] = "d9c875ded95daed312016f5c77f84db1"

# MelonDS emulator
class MelonDS(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "melonDS"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.NINTENDO_DS,
            config.Platform.NINTENDO_DSI
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

    # Setup
    def Setup(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("melonDS", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "melonDS-emu",
                github_repo = "melonDS",
                starts_with = "melonDS",
                ends_with = "windows-x86_64.zip",
                search_file = "melonDS.exe",
                install_name = "melonDS",
                install_dir = programs.GetProgramInstallDir("melonDS", "windows"),
                backups_dir = programs.GetProgramBackupDir("melonDS", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("melonDS", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/melonDS.git",
                output_file = "melonDS-x86_64.AppImage",
                install_name = "melonDS",
                install_dir = programs.GetProgramInstallDir("melonDS", "linux"),
                backups_dir = programs.GetProgramBackupDir("melonDS", "linux"),
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
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("melonDS", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("melonDS", "windows"),
                install_name = "melonDS",
                install_dir = programs.GetProgramInstallDir("melonDS", "windows"),
                search_file = "melonDS.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("melonDS", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("melonDS", "linux"),
                install_name = "melonDS",
                install_dir = programs.GetProgramInstallDir("melonDS", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):

        # Use default params if not provided
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup melonDS config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = paths.join_paths(environment.GetLockerGamingEmulatorSetupDir("melonDS"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify melonDS system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.GetLockerGamingEmulatorSetupDir("melonDS"), filename),
                    dest = paths.join_paths(programs.GetEmulatorPathConfigValue("melonDS", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup melonDS system files")
                    return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
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
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
