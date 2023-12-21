# Imports
import os, os.path
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
[config]
amiga_model = A500
governor_warning = 0
"""
config_files["FS-UAE/windows/Portable.ini"] = ""
config_files["FS-UAE/windows/Configurations/Default.fs-uae"] = config_file_general
config_files["FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"] = config_file_general

# FSUAE emulator
class FSUAE(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "FS-UAE"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_commodore_amiga
        ]

    # Get config
    def GetConfig(self):
        return {
            "FS-UAE": {
                "program": {
                    "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "FS-UAE/windows",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE"
                },
                "config_file": {
                    "windows": "FS-UAE/windows/Configurations/Default.fs-uae",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("FS-UAE", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "FrodeSolheim",
                github_repo = "fs-uae",
                starts_with = "FS-UAE",
                ends_with = "Windows_x86-64.zip",
                search_file = "Plugin.ini",
                install_name = "FS-UAE",
                install_dir = programs.GetProgramInstallDir("FS-UAE", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("FS-UAE", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/FrodeSolheim/fs-uae/releases/download/v3.1.66/fs-uae-3.1.66.tar.xz",
                output_name = "FS-UAE",
                output_dir = programs.GetProgramInstallDir("FS-UAE", "linux"),
                build_cmd = [
                    "cd", "fs-uae-3.1.66",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                    {"from": "Source/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/fs-uae", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
                ],
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

        # Copy setup files
        for platform in ["windows", "linux"]:
            system.CopyContents(
                src = environment.GetSyncedGameEmulatorSetupDir("FS-UAE"),
                dest = programs.GetEmulatorPathConfigValue("FS-UAE", "setup_dir", platform),
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
            programs.GetEmulatorProgram("FS-UAE"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=1"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            json_data = json_data,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
