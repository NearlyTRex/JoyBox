# Imports
import os
import os.path
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
[ports.qt]
gb.bios=EMULATOR_SETUP_ROOT/bios/gb_bios.bin
gbc.bios=EMULATOR_SETUP_ROOT/bios/gbc_bios.bin
gba.bios=EMULATOR_SETUP_ROOT/bios/gba_bios.bin
sgb.bios=EMULATOR_SETUP_ROOT/bios/sgb_bios.bin
savegamePath=GAME_SAVE_DIR
"""
config_files["mGBA/windows/portable.ini"] = ""
config_files["mGBA/windows/config.ini"] = config_file_general
config_files["mGBA/linux/mGBA.AppImage.home/.config/mgba/config.ini"] = config_file_general

# System files
system_files = {}
system_files["bios/gbc_bios.bin"] = "dbfce9db9deaa2567f6a84fde55f9680"
system_files["bios/sgb_bios.bin"] = "d574d4f9c12f305074798f54c091a8b4"
system_files["bios/gba_bios.bin"] = "a860e8c0b6d573d191e4ec7db1b1e4f6"
system_files["bios/gb_bios.bin"] = "32fbbd84168d3482956eb3c5051637f5"

# MGBA emulator
class MGBA(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "mGBA"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.NINTENDO_GAME_BOY_ADVANCE,
            config.Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER,
            config.Platform.NINTENDO_GAME_BOY,
            config.Platform.NINTENDO_GAME_BOY_COLOR,
            config.Platform.NINTENDO_SUPER_GAME_BOY,
            config.Platform.NINTENDO_SUPER_GAME_BOY_COLOR
        ]

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

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("mGBA", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = "win64.7z",
                search_file = "mGBA.exe",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "windows"),
                backups_dir = programs.GetProgramBackupDir("mGBA", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup mGBA")

        # Download linux program
        if programs.ShouldProgramBeInstalled("mGBA", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "mgba-emu",
                github_repo = "mgba",
                starts_with = "mGBA",
                ends_with = ".appimage",
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "linux"),
                backups_dir = programs.GetProgramBackupDir("mGBA", "linux"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup mGBA")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("mGBA", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("mGBA", "windows"),
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "windows"),
                search_file = "mGBA.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup mGBA")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("mGBA", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("mGBA", "linux"),
                install_name = "mGBA",
                install_dir = programs.GetProgramInstallDir("mGBA", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup mGBA")

    # Configure
    def Configure(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup mGBA config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetLockerGamingEmulatorSetupDir("mGBA"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify mGBA system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = os.path.join(environment.GetLockerGamingEmulatorSetupDir("mGBA"), filename),
                    dest = os.path.join(programs.GetEmulatorPathConfigValue("mGBA", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                system.AssertCondition(success, "Could not setup mGBA system files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("mGBA"),
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
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
