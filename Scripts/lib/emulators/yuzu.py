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
import archive
import nintendo
import gui
import ini
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[Data%20Storage]
dump_directory="EMULATOR_SETUP_ROOT/dump"
load_directory="EMULATOR_SETUP_ROOT/load"
nand_directory="EMULATOR_SETUP_ROOT/nand"
sdmc_directory="EMULATOR_SETUP_ROOT/sdmc"
tas_directory="EMULATOR_SETUP_ROOT/tas"

[UI]
Screenshots\screenshot_path="EMULATOR_SETUP_ROOT/screenshots"
"""
config_files["Yuzu/windows/user/config/qt-config.ini"] = config_file_general
config_files["Yuzu/linux/Yuzu.AppImage.home/.config/yuzu/qt-config.ini"] = config_file_general

# System files
system_files = {}
system_files["sysdata/fuses.bin"] = "15437331fa1cf96fdeb61f39230a9526"
system_files["sysdata/BOOT0"] = "cf9fb34f7702b26aa73be5acf96ee9c6"
system_files["sysdata/BCPKG2-1-Normal-Main.bin"] = "216f85fc652a56391c11f08bd4f79d4b"
system_files["sysdata/pkg1_decr.bin"] = "396fc1f6445e86b75dd521cba1d94d52"
system_files["sysdata/PRODINFO.bin"] = "13ce15ab30e7c2d4ddf3eff40fb31d82"
system_files["sysdata/secmon.bin"] = "45bc865a44a01358c137cda7c6009e21"
system_files["keys/console.keys"] = "67b5b410da0a9bdcb37f92bd32a4c63d"
system_files["keys/title.keys"] = "b5890c3d737880f6dd3751ffec5b128b"
system_files["keys/prod.keys"] = "4ed853d4a52e6b9b9e11954f155ecb8a"

# Yuzu emulator
class Yuzu(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Yuzu"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.NINTENDO_SWITCH,
            config.Platform.NINTENDO_SWITCH_ESHOP
        ]

    # Get config
    def GetConfig(self):

        # Get switch info
        profile_user_id = ini.GetIniValue("UserData.Switch", "profile_user_id")
        profile_account_name = ini.GetIniValue("UserData.Switch", "profile_account_name")
        if not nintendo.IsValidSwitchProfileInfo(profile_user_id, profile_account_name):
            system.LogWarning("No Switch profile found in ini, using default")
            profile_user_id = "F6F389D41D6BC0BDD6BD928C526AE556"
            profile_account_name = "yuzu"

        # Return config
        return {
            "Yuzu": {
                "program": {
                    "windows": "Yuzu/windows/yuzu.exe",
                    "linux": "Yuzu/linux/Yuzu.AppImage"
                },
                "save_dir": {
                    "windows": "Yuzu/windows/user/nand/user/save/0000000000000000/%s" % profile_user_id,
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand/user/save/0000000000000000/%s" % profile_user_id
                },
                "setup_dir": {
                    "windows": "Yuzu/windows/user",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu"
                },
                "config_file": {
                    "windows": "Yuzu/windows/user/config/qt-config.ini",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.config/yuzu/qt-config.ini"
                },
                "profiles_file": {
                    "windows": "Yuzu/windows/user/nand/system/save/8000000000000010/su/avators/profiles.dat",
                    "linux": "Yuzu/linux/Yuzu.AppImage.home/.local/share/yuzu/nand/system/save/8000000000000010/su/avators/profiles.dat"
                },
                "profile_user_id": profile_user_id,
                "profile_account_name": profile_account_name,
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for nsp_file in system.BuildFileListByExtensions(package_dir, extensions = [".nsp"]):
                    success = nintendo.InstallSwitchNSP(
                        nsp_file = nsp_file,
                        nand_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir"), "nand"),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False
        return True

    # Setup
    def Setup(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Yuzu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Yuzu", "windows"),
                install_name = "Yuzu",
                install_dir = programs.GetProgramInstallDir("Yuzu", "windows"),
                preferred_archive = "Windows-Yuzu-EA-4176",
                search_file = "yuzu.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Yuzu")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Yuzu", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Yuzu", "linux"),
                install_name = "Yuzu",
                install_dir = programs.GetProgramInstallDir("Yuzu", "linux"),
                preferred_archive = "Linux-Yuzu-EA-4176",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Yuzu")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):
        return self.Setup(verbose = verbose, pretend_run = pretend_run,exit_on_failure = exit_on_failure)

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
                system.LogError("Could not setup Yuzu config files")
                return False

        # Create profiles
        for platform in ["windows", "linux"]:
            success = nintendo.CreateSwitchProfilesDat(
                profiles_file = programs.GetEmulatorPathConfigValue("Yuzu", "profiles_file", platform),
                user_id = programs.GetEmulatorConfigValue("Yuzu", "profile_user_id"),
                account_name = programs.GetEmulatorConfigValue("Yuzu", "profile_account_name"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Yuzu profiles")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Yuzu"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify Yuzu system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Yuzu"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("Yuzu", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Could not setup Yuzu system files")
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
            programs.GetEmulatorProgram("Yuzu"),
            "-g", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
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
