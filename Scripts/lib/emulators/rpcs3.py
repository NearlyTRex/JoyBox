# Imports
import os
import os.path
import sys

# Local imports
import config
import cache
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
config_files["RPCS3/windows/GuiConfigs/CurrentSettings.ini"] = ""
config_files["RPCS3/linux/RPCS3.AppImage.home/.config/rpcs3/GuiConfigs/CurrentSettings.ini"] = ""

# System files
system_files = {}
system_files["dev_flash.zip"] = "08f2dc11bd3c7dfefae48ebbbc8caf55"

# RPCS3 emulator
class RPCS3(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "RPCS3"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_sony_playstation_3,
            config.game_subcategory_sony_playstation_network_ps3
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

    # Setup
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("RPCS3", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-win",
                starts_with = "rpcs3",
                ends_with = "win64.7z",
                search_file = "rpcs3.exe",
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "windows"),
                backups_dir = programs.GetProgramBackupDir("RPCS3", "windows"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RPCS3")

        # Download linux program
        if programs.ShouldProgramBeInstalled("RPCS3", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-linux",
                starts_with = "rpcs3",
                ends_with = ".AppImage",
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "linux"),
                backups_dir = programs.GetProgramBackupDir("RPCS3", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RPCS3")

    # Setup offline
    def SetupOffline(self, verbose = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("RPCS3", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RPCS3", "windows"),
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "windows"),
                search_file = "rpcs3.exe",
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RPCS3")

        # Setup linux program
        if programs.ShouldProgramBeInstalled("RPCS3", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("RPCS3", "linux"),
                install_name = "RPCS3",
                install_dir = programs.GetProgramInstallDir("RPCS3", "linux"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RPCS3")

    # Configure
    def Configure(self, verbose = False, exit_on_failure = False):

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup RPCS3 config files")

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                filename = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), filename),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify RPCS3 system file %s" % filename)

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["dev_flash"]:
                if os.path.exists(os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip")):
                    success = archive.ExtractArchive(
                        archive_file = os.path.join(environment.GetSyncedGameEmulatorSetupDir("RPCS3"), obj + ".zip"),
                        extract_dir = os.path.join(programs.GetEmulatorPathConfigValue("RPCS3", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    system.AssertCondition(success, "Could not extract RPCS3 system files")

    # Launch
    def Launch(
        self,
        game_info,
        capture_type,
        fullscreen = False,
        verbose = False,
        exit_on_failure = False):

        # Get game info
        game_platform = game_info.get_platform()
        game_save_dir = game_info.get_save_dir()
        game_cache_dir = game_info.get_local_cache_dir()

        # Install game to cache
        cache.InstallGameToCache(
            game_info = game_info,
            verbose = verbose)

        # Copy exdata files
        if game_platform == config.game_subcategory_sony_playstation_network_ps3:
            for exdata_file in system.BuildFileListByExtensions(game_cache_dir, extensions = [".rap", ".edat"]):
                system.SmartCopy(
                    src = exdata_file,
                    dest = os.path.join(game_save_dir, "exdata"),
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
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
