# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
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
    def get_name(self):
        return "BasiliskII"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.OTHER_APPLE_MACOS_8
        ]

    # Get config
    def get_config(self):
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
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("BasiliskII", "windows"):
            success = release.download_general_release(
                archive_url = "https://surfdrive.surf.nl/files/index.php/s/IVkakW3BztSohqH/download",
                search_file = "BasiliskII.exe",
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "windows"),
                backups_dir = programs.get_program_backup_dir("BasiliskII", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False

        # Download linux program
        if programs.should_program_be_installed("BasiliskII", "linux"):
            success = release.download_github_release(
                github_user = "Korkman",
                github_repo = "macemu-appimage-builder",
                starts_with = "BasiliskII-x86_64",
                ends_with = ".AppImage",
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "linux"),
                backups_dir = programs.get_program_backup_dir("BasiliskII", "linux"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BasiliskII", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BasiliskII", "windows"),
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "windows"),
                search_file = "BasiliskII.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False

        # Setup linux program
        if programs.should_program_be_installed("BasiliskII", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BasiliskII", "linux"),
                install_name = "BasiliskII",
                install_dir = programs.get_program_install_dir("BasiliskII", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BasiliskII config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.calculate_file_md5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("BasiliskII"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify BasiliskII system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("BasiliskII"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("BasiliskII", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup BasiliskII system files")
                    return False
        return True

    # Launch
    def launch(
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
            programs.get_emulator_program("BasiliskII"),
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
