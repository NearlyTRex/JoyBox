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
import archive
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["EKA2L1/windows/config.yml"] = ""
config_files["EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/config.yml"] = ""

# System files
system_files = {}
system_files["data.zip"] = "e4c10430ddc600cdffff1fb348a6b0c3"

# EKA2L1 emulator
class EKA2L1(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "EKA2L1"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_nokia_ngage
        ]

    # Get config
    def GetConfig(self):
        return {
            "EKA2L1": {
                "program": {
                    "windows": "EKA2L1/windows/eka2l1_qt.exe",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage"
                },
                "save_dir": {
                    "windows": "EKA2L1/windows/data/drives/c/system/apps",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/data/drives/c/system/apps"
                },
                "setup_dir": {
                    "windows": "EKA2L1/windows",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1"
                },
                "config_file": {
                    "windows": "EKA2L1/windows/config.yml",
                    "linux": "EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/config.yml"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("EKA2L1", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "EKA2L1-Windows-x86_64",
                ends_with = ".zip",
                search_file = "eka2l1_qt.exe",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "windows"),
                backups_dir = programs.GetProgramBackupDir("EKA2L1", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup EKA2L1")

        # Download linux program
        if programs.ShouldProgramBeInstalled("EKA2L1", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "EKA2L1-Linux-x86_64",
                ends_with = ".AppImage",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "linux"),
                backups_dir = programs.GetProgramBackupDir("EKA2L1", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup EKA2L1")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("EKA2L1", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("EKA2L1", "windows"),
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "windows"),
                search_file = "eka2l1_qt.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup EKA2L1")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("EKA2L1", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("EKA2L1", "linux"),
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup EKA2L1")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup EKA2L1 config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetLockerGameEmulatorSetupDir("EKA2L1"), filename),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify EKA2L1 system file %s" % filename)

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["data"]:
                if os.path.exists(os.path.join(environment.GetLockerGameEmulatorSetupDir("EKA2L1"), obj + ".zip")):
                    success = archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetLockerGameEmulatorSetupDir("EKA2L1"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("EKA2L1", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not extract EKA2L1 system files")

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
            programs.GetEmulatorProgram("EKA2L1"),
            "--mount", config.token_game_dir,
            "--app", config.token_game_name
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
