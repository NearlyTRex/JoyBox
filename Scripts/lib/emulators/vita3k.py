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
import archive
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
---
pref-path: $EMULATOR_SETUP_ROOT
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
            config.game_subcategory_sony_playstation_network_psv,
            config.game_subcategory_sony_playstation_vita
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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("Vita3K", "windows"):
            success = network.DownloadLatestGithubRelease(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "windows-latest",
                ends_with = ".zip",
                search_file = "Vita3K.exe",
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

        # Download linux program
        if programs.ShouldProgramBeInstalled("Vita3K", "linux"):
            success = network.DownloadLatestGithubRelease(
                github_user = "Vita3K",
                github_repo = "Vita3K",
                starts_with = "Vita3K-x86_64",
                ends_with = ".AppImage",
                search_file = "Vita3K-x86_64.AppImage",
                install_name = "Vita3K",
                install_dir = programs.GetProgramInstallDir("Vita3K", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup Vita3K config files")

        # Extract setup files
        for platform in ["windows", "linux"]:
            for obj in ["os0", "sa0", "vs0"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("Vita3K"), obj + ".zip")):
                    success = archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Vita3K"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Vita3K", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not setup Vita3K system files")

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
            programs.GetEmulatorProgram("Vita3K")
        ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
