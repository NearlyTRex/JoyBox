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
displaycolordepth 0
disk
cdrom /dev/cdrom
extfs /
screen dga/1024/768
seriala /dev/ttyS0
serialb /dev/ttyS1
udptunnel false
udpport 6066
rom $EMULATOR_SETUP_ROOT/quadra.rom
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
system_files["bios/quadra.rom"] = "69489153dde910a69d5ae6de5dd65323"

# BasiliskII emulator
class BasiliskII(emulatorbase.EmulatorBase):

    # Get name
    def GetName(self):
        return "BasiliskII"

    # Get platforms
    def GetPlatforms(self):
        return [
            config.game_subcategory_apple_macos_8
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
    def Setup(self, verbose = False, exit_on_failure = False):

        # Download windows program
        if programs.ShouldProgramBeInstalled("BasiliskII", "windows"):
            success = network.DownloadGeneralRelease(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/C7E6HIZKWuHHR1P/download",
                search_file = "BasiliskII.exe",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "windows"),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BasiliskII")

        # Download linux program
        if programs.ShouldProgramBeInstalled("BasiliskII", "linux"):
            success = network.DownloadLatestGithubRelease(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "BasiliskII-x86_64",
                ends_with = ".AppImage",
                search_file = "BasiliskII-x86_64.AppImage",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "linux"),
                get_latest = True,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BasiliskII")

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = system.TouchFile(
                src = os.path.join(environment.GetEmulatorsRootDir(), config_filename),
                contents = config_contents.strip(),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BasiliskII config files")

        # Copy setup files
        for platform in ["windows", "linux"]:
            success = system.CopyContents(
                src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("BasiliskII"), "bios"),
                dest = programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", platform),
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            system.AssertCondition(success, "Could not setup BasiliskII system files")

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
            programs.GetEmulatorProgram("BasiliskII"),
            "--disk", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--nogui", "true"
            ]

        # Launch game
        emulatorcommon.SimpleLaunch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
