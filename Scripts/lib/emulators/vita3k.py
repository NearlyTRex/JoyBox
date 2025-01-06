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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
---
pref-path: EMULATOR_SETUP_ROOT
...
"""
config_files["Vita3K/windows/config.yml"] = config_file_general
config_files["Vita3K/linux/Vita3K.AppImage.home/.config/Vita3K/config.yml"] = config_file_general

# System files
system_files = {}
system_files["vs0.zip"] = "f3c4ec664b6a2cba130eb5b3977dbc23"
system_files["os0.zip"] = "301589989b48da90e6db41b85d2b0acc"
system_files["sa0.zip"] = "c248704ab44184c7c47f9bcc27854696"

# Vita3K emulator
class Vita3K(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Vita3K"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.SONY_PLAYSTATION_NETWORK_PSV,
            config.Platform.SONY_PLAYSTATION_VITA
        ]

    # Get config
    def GetConfig(self):
        return {
            "Vita3K": {
                "program": {
                    "windows": "Vita3K/windows/Vita3K.exe",
                    "linux": "Vita3K/linux/Vita3K.AppImage"
                },
                "save_dir": {
                    "windows": "Vita3K/windows/data/ux0/user",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/user"
                },
                "app_dir": {
                    "windows": "Vita3K/windows/data/ux0/app",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K/ux0/app"
                },
                "setup_dir": {
                    "windows": "Vita3K/windows/data",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.local/share/Vita3K/Vita3K"
                },
                "config_file": {
                    "windows": "Vita3K/windows/config.yml",
                    "linux": "Vita3K/linux/Vita3K.AppImage.home/.config/Vita3K/config.yml"
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
        if programs.ShouldProgramBeInstalled("Vita3K", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "windows-latest",
                ends_with = ".zip",
                search_file = "Vita3K.exe",
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "windows"),
                backups_dir = programs.GetProgramBackupDir("Vita3K", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Vita3K", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "Vita3K-x86_64",
                ends_with = ".AppImage",
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "linux"),
                backups_dir = programs.GetProgramBackupDir("Vita3K", "linux"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Vita3K", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Vita3K", "windows"),
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "windows"),
                search_file = "Vita3K.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Vita3K", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Vita3K", "linux"),
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

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
            system.AssertCondition(success, "Could not setup Vita3K config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Vita3K"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Vita3K system file %s" % filename)

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["os0", "sa0", "vs0"]:
                if os.path.exists(system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Vita3K"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.ExtractArchive(
                        archive_file = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Vita3K"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = system.JoinPaths(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not extract Vita3K system files")

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
            programs.GetEmulatorProgram("Vita3K")
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
