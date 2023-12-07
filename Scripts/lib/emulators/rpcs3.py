# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import cache
import environment
import system
import network
import programs
import launchcommon
import gui

# Local imports
from . import base

# RPCS3 emulator
class RPCS3(base.EmulatorBase):

    # Get name
    def GetName():
        return "RPCS3"

    # Get platforms
    def GetPlatforms():
        return config.rpcs3_platforms

    # Get config
    def GetConfig():
        return {
            "RPCS3": {
                "program": {
                    "windows": "RPCS3/windows/rpcs3.exe",
                    "linux": "RPCS3/linux/RPCS3.AppImage"
                },
                "save_dir": {
                    "windows": "RPCS3/windows/dev_hdd0/home/00000001",
                    "linux": "RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3/dev_hdd0/home/00000001"
                },
                "setup_dir": {
                    "windows": "RPCS3/windows",
                    "linux": "RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3"
                },
                "config_file": {
                    "windows": None,
                    "linux": None
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("RPCS3", "windows"):
            network.DownloadLatestGithubRelease(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-win",
                starts_with = "rpcs3",
                ends_with = "win64.7z",
                search_file = "rpcs3.exe",
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "windows"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("RPCS3", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-linux",
                starts_with = "rpcs3",
                ends_with = ".AppImage",
                search_file = "RPCS3.AppImage",
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "linux"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup():
        for obj in ["dev_flash"]:
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "linux"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "linux"), obj),
                    skip_existing = True,
                    verbose = config.default_flag_verbose,
                    exit_on_failure = config.default_flag_exit_on_failure)
            if not os.path.exists(os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "windows"), obj)):
                archive.ExtractArchive(
                    archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                    extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", "windows"), obj),
                    skip_existing = True,
                    verbose = False,
                    exit_on_failure = False)

    # Launch
    def Launch(
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

        # Get launch categories
        launch_supercategory, launch_category, launch_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)

        # Install game to cache
        cache.InstallGameToCache(
            game_platform = launch_platform,
            game_name = launch_name,
            game_file = launch_file,
            game_artwork = launch_artwork,
            verbose = config.default_flag_verbose)

        # Get directories
        cache_dir = environment.GetCachedRomDir(launch_category, launch_subcategory, launch_name)
        exdata_dir = os.path.join(launch_save_dir, "exdata")

        # Make directories
        system.MakeDirectory(
            dir = exdata_dir,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

        # Copy exdata files
        if launch_platform == "Sony PlayStation Network - PlayStation 3":
            for exdata_file in system.BuildFileListByExtensions(cache_dir, extensions = [".rap", ".edat"]):
                system.CopyFileOrDirectory(
                    src = exdata_file,
                    dest = exdata_dir,
                    verbose = config.default_flag_verbose)

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("RPCS3"),
            config.token_game_file
        ]

        # Launch game
        launchcommon.SimpleLaunch(
            launch_cmd = launch_cmd,
            launch_name = launch_name,
            launch_platform = launch_platform,
            launch_file = launch_file,
            launch_artwork = launch_artwork,
            launch_save_dir = launch_save_dir,
            launch_capture_type = launch_capture_type)
