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
import launchcommon
import gui

# Local imports
from . import base

# Config files
config_files = {}
config_files["BasiliskII/windows/BasiliskII_prefs"] = """
displaycolordepth 0
disk
cdrom /dev/cdrom
extfs /
screen dga/1024/768
seriala /dev/ttyS0
serialb /dev/ttyS1
udptunnel false
udpport 6066
rom $EMULATOR_MAIN_ROOT/BasiliskII/windows/quadra.rom
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
config_files["BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII/prefs"] = """
displaycolordepth 0
disk
cdrom /dev/cdrom
extfs /
screen dga/1024/768
seriala /dev/ttyS0
serialb /dev/ttyS1
udptunnel false
udpport 6066
rom $EMULATOR_MAIN_ROOT/BasiliskII/linux/BasiliskII.AppImage.home/.config/BasiliskII/quadra.rom
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

# BasiliskII emulator
class BasiliskII(base.EmulatorBase):

    # Get name
    def GetName(self):
        return "BasiliskII"

    # Get platforms
    def GetPlatforms(self):
        return config.basiliskii_platforms

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

    # Download
    def Download(self, force_downloads = False):
        if force_downloads or programs.ShouldProgramBeInstalled("BasiliskII", "windows"):
            network.DownloadGeneralRelease(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/C7E6HIZKWuHHR1P/download",
                search_file = "BasiliskII.exe",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "windows"),
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)
        if force_downloads or programs.ShouldProgramBeInstalled("BasiliskII", "linux"):
            network.DownloadLatestGithubRelease(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "BasiliskII-x86_64",
                ends_with = ".AppImage",
                search_file = "BasiliskII-x86_64.AppImage",
                install_name = "BasiliskII",
                install_dir = programs.GetProgramInstallDir("BasiliskII", "linux"),
                get_latest = True,
                verbose = config.default_flag_verbose,
                exit_on_failure = config.default_flag_exit_on_failure)

    # Setup
    def Setup(self):
        system.CopyContents(
            src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("BasiliskII"), "bios"),
            dest = programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", "linux"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)
        system.CopyContents(
            src = os.path.join(environment.GetSyncedGameEmulatorSetupDir("BasiliskII"), "bios"),
            dest = programs.GetEmulatorPathConfigValue("BasiliskII", "setup_dir", "windows"),
            skip_existing = True,
            verbose = config.default_flag_verbose,
            exit_on_failure = config.default_flag_exit_on_failure)

    # Launch
    def Launch(
        self,
        launch_name,
        launch_platform,
        launch_file,
        launch_artwork,
        launch_save_dir,
        launch_general_save_dir,
        launch_capture_type):

        # Get launch command
        launch_cmd = [
            programs.GetEmulatorProgram("BasiliskII"),
            "--disk", config.token_game_file
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
