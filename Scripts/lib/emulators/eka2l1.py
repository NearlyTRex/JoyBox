# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import network
import programs
import archive
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["EKA2L1/windows/config.yml"] = ""
config_files["EKA2L1/linux/EKA2L1.AppImage.home/.local/share/EKA2L1/config.yml"] = ""

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

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("EKA2L1", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "windows-latest",
                ends_with = ".zip",
                search_file = "eka2l1_qt.exe",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("EKA2L1", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "EKA2L1",
                github_repo = "EKA2L1",
                starts_with = "ubuntu-latest",
                ends_with = ".AppImage",
                search_file = "ubuntu-latest.AppImage",
                install_name = "EKA2L1",
                install_dir = programs.GetProgramInstallDir("EKA2L1", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)

        # Extract setup files
        for platform in ["windows", "linux"]:
            for obj in ["data"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("EKA2L1"), obj + ".zip")):
                    archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("EKA2L1"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("EKA2L1", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)

    # Launch
    def Launch(
        self,
        json_data,
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
            json_data = json_data,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
