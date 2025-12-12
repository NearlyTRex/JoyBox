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
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
displaycolordepth 0
disk
cdrom /dev/cdrom
extfs /
screen dga/1024/768
seriala /dev/ttyS0
serialb /dev/ttyS1
udptunnel false
udpport 6066
rom EMULATOR_SETUP_ROOT/quadra.rom
bootdrive 0
bootdriver 0
ramsize 67108864
frameskip 1
modelid 14
cpu 4
fpu true
nocdrom false
nosound false
noclipconversion false
nogui false
jit false
jitfpu true
jitdebug false
jitcachesize 8192
jitlazyflush true
jitinline true
keyboardtype 5
keycodes false
mousewheelmode 1
mousewheellines 3
hotkey 0
scale_nearest false
scale_integer false
yearofs 0
dayofs 0
mag_rate 0
swap_opt_cmd true
ignoresegv true
sound_buffer 0
name_encoding 0
delay 0
dsp /dev/dsp
mixer /dev/mixer
idlewait true
sdlrender software
"""
config_files["BasiliskII/windows/BasiliskII_prefs"] = config_file_general
config_files["BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII/prefs"] = config_file_general

# System files
system_files = {}
system_files["quadra.rom"] = "69489153dde910a69d5ae6de5dd65323"

# BasiliskII emulator
class BasiliskII(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BasiliskII"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.Platform.OTHER_APPLE_MACOS_8
        ]

    # Get config
    def GetConfig(self):
        return {
            "BasiliskII": {
                "program": {
                    "windows": "BasiliskII/windows/BasiliskII.exe",
                    "linux": "BasiliskII/linux/BasiliskII.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "BasiliskII/windows",
                    "linux": "BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII"
                },
                "config_file": {
                    "windows": "BasiliskII/windows/BasiliskII_prefs",
                    "linux": "BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII/prefs"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Setup
    def Setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.ShouldProgramBeInstalled("BasiliskII", "windows"):
            success = release.DownloadGeneralRelease(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/IVkakW3BztSohqH/download",
                search_file = "BasiliskII.exe",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "windows"),
                backups_dir = programs.GetProgramBackupDir("BasiliskII", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BasiliskII")
                return False

        # Download linux program
        if programs.ShouldProgramBeInstalled("BasiliskII", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "BasiliskII-x86_64",
                ends_with = ".AppImage",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "linux"),
                backups_dir = programs.GetProgramBackupDir("BasiliskII", "linux"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BasiliskII")
                return False
        return True

    # Setup offline
    def SetupOffline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.ShouldProgramBeInstalled("BasiliskII", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BasiliskII", "windows"),
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "windows"),
                search_file = "BasiliskII.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BasiliskII")
                return False

        # Setup linux program
        if programs.ShouldProgramBeInstalled("BasiliskII", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.GetProgramBackupDir("BasiliskII", "linux"),
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BasiliskII")
                return False
        return True

    # Configure
    def Configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = system.JoinPaths(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                system.LogError("Could not setup BasiliskII config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("BasiliskII"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                system.LogError("Could not verify BasiliskII system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = system.SmartCopy(
                    src = system.JoinPaths(environment.GetLockerGamingEmulatorSetupDir("BasiliskII"), filename),
                    dest = system.JoinPaths(programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    system.LogError("Could not setup BasiliskII system files")
                    return False
        return True

    # Launch
    def Launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("BasiliskII"),
            "--disk", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--nogui", "true"
            ]

        # Launch game
        return emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
