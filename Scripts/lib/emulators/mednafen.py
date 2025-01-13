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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Mednafen/windows/mednafen.cfg"] = ""
config_files["Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"] = ""

# System files
system_files = {}
system_files["firmware/lynxboot.img"] = "fcd403db69f54290b51035d82f835e7b"

# Mednafen emulator
class Mednafen(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "Mednafen"

    # Get platforms
    def GetPlatforms(self):
        return [

            # Nintendo
            config.Platform.NINTENDO_VIRTUAL_BOY,

            # Other
            config.Platform.OTHER_ATARI_LYNX
        ]

    # Get config
    def GetConfig(self):
        return {
            "Mednafen": {
                "program": {
                    "windows": "Mednafen/windows/mednafen.exe",
                    "linux": "Mednafen/linux/Mednafen.AppImage"
                },
                "save_dir": {
                    "windows": "Mednafen/windows/sav",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/sav"
                },
                "setup_dir": {
                    "windows": "Mednafen/windows",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen"
                },
                "config_file": {
                    "windows": "Mednafen/windows/mednafen.cfg",
                    "linux": "Mednafen/linux/Mednafen.AppImage.home/.mednafen/mednafen.cfg"
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
        if programs.ShouldProgramBeInstalled("Mednafen", "windows"):
            success = release.DownloadWebpageRelease(
                webpage_url = "https://mednafen.github.io",
                webpage_base_url = "https://mednafen.github.io",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE-win64.zip",
                search_file = "mednafen.exe",
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "windows"),
                backups_dir = programs.GetProgramBackupDir("Mednafen", "windows"),
                get_latest = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mednafen")
                return False

        # Build linux program
        if programs.ShouldProgramBeInstalled("Mednafen", "linux"):
            success = release.BuildAppImageFromSource(
                webpage_url = "https://mednafen.github.io",
                webpage_base_url = "https://mednafen.github.io",
                starts_with = "https://mednafen.github.io/releases/files/mednafen",
                ends_with = "UNSTABLE.tar.xz",
                output_file = "App-x86_64.AppImage",
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "linux"),
                backups_dir = programs.GetProgramBackupDir("Mednafen", "linux"),
                build_cmd = [
                    "cd", "mednafen",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/mednafen/src/mednafen", "to": "AppImage/usr/bin/mednafen"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/mednafen", "to": "AppRun"}
                ],
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mednafen")
                return False
        return True

    # Setup offline
    def SetupOffline(self, verbose = False, pretend_run = False, exit_on_failure = False):

        # Setup windows program
        if programs.ShouldProgramBeInstalled("Mednafen", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Mednafen", "windows"),
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "windows"),
                search_file = "mednafen.exe",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mednafen")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("Mednafen", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("Mednafen", "linux"),
                install_name = "Mednafen",
                install_dir = programs.GetProgramInstallDir("Mednafen", "linux"),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                system.LogError("Could not setup Mednafen")
                return False
        return True

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
                system.LogError("Could not setup Mednafen config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Mednafen"), filename),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            success = (expected_md5 == actual_md5)
            system.AssertCondition(success, "Could not verify Mednafen system file %s" % filename)

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("Mednafen"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("Mednafen", "setup_dir", platform), filename),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                system.LogError("Could not setup Mednafen system files")
                return False
        return True

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
            programs.GetEmulatorProgram("Mednafen"),
            config.token_game_file
        ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
