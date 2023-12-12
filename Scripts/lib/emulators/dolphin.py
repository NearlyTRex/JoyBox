# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import environment
import system
import network
import programs
import archive
import nintendo
import launchcommon
import gui

# Local imports
from . import base

# Config files
config_files = {}
config_files["Dolphin/windows/portable.txt"] = ""
config_files["Dolphin/windows/User/Config/Dolphin.ini"] = ""
config_files["Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/Dolphin.ini"] = ""

# Dolphin emulator
class Dolphin(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "Dolphin"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Nintendo Gamecube",
            "Nintendo Wii"
        ]

    # Get config
    def GetConfig(self):
        return {
            "Dolphin": {
                "program": {
                    "windows": "Dolphin/windows/Dolphin.exe",
                    "linux": "Dolphin/linux/Dolphin.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "save_base_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
                },
                "save_sub_dirs": {

                    # Nintendo
                    "Nintendo Gamecube": "GC",
                    "Nintendo Wii": "Wii/title/00010000"
                },
                "setup_dir": {
                    "windows": "Dolphin/windows/User",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.local/share/dolphin-emu"
                },
                "config_file": {
                    "windows": "Dolphin/windows/User/Config/Dolphin.ini",
                    "linux": "Dolphin/linux/Dolphin.AppImage.home/.config/dolphin-emu/Dolphin.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Install add-ons
    def InstallAddons(self, dlc_dirs = [], update_dirs = [], verbose = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for wad_file in system.BuildFileListByExtensions(package_dir, extensions = [".wad"]):
                    pass

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
        if force_downloads or programs.ShouldProgramBeInstalled("Dolphin", "windows"):
            network.DownloadLatestWebpageRelease(
                webpage_url = "https://dolphin-emu.org/download/",
                starts_with = "https://dl.dolphin-emu.org/builds",
                ends_with = "x64.7z",
                search_file = "Dolphin.exe",
                install_name = "Dolphin",
                install_dir = programs.GetProgramInstallDir("Dolphin", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("Dolphin", "linux"):
            network.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Dolphin.git",
                output_name = "Dolphin",
                output_dir = programs.GetProgramInstallDir("Dolphin", "linux"),
                build_cmd = [
                    "cmake", "..", "-DLINUX_LOCAL_DEV=true", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/Binaries/dolphin-emu", "to": "AppImage/usr/bin/dolphin-emu"},
                    {"from": "Source/Build/Binaries/dolphin-tool", "to": "AppImage/usr/bin/dolphin-tool"},
                    {"from": "Source/Data/Sys", "to": "AppImage/usr/bin/Sys"},
                    {"from": "Source/Data/dolphin-emu.desktop", "to": "AppImage/dolphin-emu.desktop"},
                    {"from": "Source/Data/dolphin-emu.png", "to": "AppImage/dolphin-emu.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/dolphin-emu", "to": "AppRun"}
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

        # Extract setup files
        for platform in ["windows", "linux"]:
            for obj in ["Wii"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip")):
                    archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("Dolphin"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("Dolphin", "setup_dir", platform), obj),
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
            programs.GetEmulatorProgram("Dolphin"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--config", "Dolphin.Display.Fullscreen=True"
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
