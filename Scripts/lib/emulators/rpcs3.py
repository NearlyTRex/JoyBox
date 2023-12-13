# Imports
import os
import os.path
import sys

# Local imports
import config
import cache
import environment
import system
import network
import programs
import archive
import launchcommon
import gui
import emulatorbase

# Config files
config_files = {}
config_files["RPCS3/windows/GuiConfigs/CurrentSettings.ini"] = ""
config_files["RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3/GuiConfigs/CurrentSettings.ini"] = ""

# RPCS3 emulator
class RPCS3(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "RPCS3"

    # Get platforms
    def GetPlatforms(self):
        return [
            "Sony PlayStation 3",
            "Sony PlayStation Network - PlayStation 3"
        ]

    # Get config
    def GetConfig(self):
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
                    "windows": "RPCS3/windows/GuiConfigs/CurrentSettings.ini",
                    "linux": "RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3/GuiConfigs/CurrentSettings.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Download
    def Download(self, force_downloads = False, verbose = False, exit_on_failure = False):
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
                verbose = verbose,
                exit_on_failure = exit_on_failure)
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
            for obj in ["dev_flash"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip")):
                    archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", platform), obj),
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

        # Get launch categories
        launch_supercategory, launch_category, launch_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)

        # Install game to cache
        cache.InstallGameToCache(
            game_platform = launch_platform,
            game_name = launch_name,
            game_file = launch_file,
            game_artwork = launch_artwork,
            verbose = verbose)

        # Get directories
        cache_dir = environment.GetCachedRomDir(launch_category, launch_subcategory, launch_name)
        exdata_dir = os.path.join(launch_save_dir, "exdata")

        # Make directories
        system.MakeDirectory(
            dir = exdata_dir,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

        # Copy exdata files
        if launch_platform == "Sony PlayStation Network - PlayStation 3":
            for exdata_file in system.BuildFileListByExtensions(cache_dir, extensions = [".rap", ".edat"]):
                system.CopyFileOrDirectory(
                    src = exdata_file,
                    dest = exdata_dir,
                    verbose = verbose)

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("RPCS3"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen",
                "--no-gui"
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
