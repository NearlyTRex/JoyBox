# Imports
import os
import os.path
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
[general]
show_welcome = false

[input.bindings]
port1 = '030003f05e0400008e02000014010000'

[sys.files]
bootrom_path = 'EMULATOR_SETUP_ROOT/bios/mcpx_1.0.bin'
flashrom_path = 'EMULATOR_SETUP_ROOT/bios/complex_4627.bin'
eeprom_path = "GAME_SAVE_DIR/eeprom.bin"
hdd_path = "GAME_SAVE_DIR/xbox_hdd.qcow2"
"""
config_files["Xemu/windows/xemu.toml"] = config_file_general
config_files["Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"] = config_file_general

# System files
system_files = {}
system_files["bios/mcpx_1.0.bin"] = "d49c52a4102f6df7bcf8d0617ac475ed"
system_files["bios/complex_4627.bin"] = "ec00e31e746de2473acfe7903c5a4cb7"
system_files["bios/complex_4627_v1.03.bin"] = "21445c6f28fca7285b0f167ea770d1e5"

# Xemu emulator
class Xemu(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Xemu"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.MICROSOFT_XBOX
        ]

    # Get config
    def get_config(self):
        return {
            "Xemu": {
                "program": {
                    "windows": "Xemu/windows/xemu.exe",
                    "linux": "Xemu/linux/Xemu.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "Xemu/windows",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu"
                },
                "config_file": {
                    "windows": "Xemu/windows/xemu.toml",
                    "linux": "Xemu/linux/Xemu.AppImage.home/.local/share/xemu/xemu/xemu.toml"
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
        if programs.should_program_be_installed("Xemu", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "mborgerson",
                github_repo = "xemu",
                starts_with = "xemu",
                ends_with = "win-release.zip",
                search_file = "xemu.exe",
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "windows"),
                backups_dir = programs.get_program_backup_dir("Xemu", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xemu")
                return False

        # Build linux program
        if programs.should_program_be_installed("Xemu", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/NearlyTRex/Xemu.git",
                output_file = "xemu-x86_64.AppImage",
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "linux"),
                backups_dir = programs.get_program_backup_dir("Xemu", "linux"),
                build_cmd = [
                    "./build.sh"
                ],
                internal_copies = [
                    {"from": "Source/dist/xemu", "to": "AppImage/usr/bin/xemu"},
                    {"from": "Source/ui/xemu.desktop", "to": "AppImage/xemu.desktop"},
                    {"from": "Source/ui/icons/xemu.svg", "to": "AppImage/xemu.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/xemu", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xemu")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Xemu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Xemu", "windows"),
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "windows"),
                search_file = "xemu.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xemu")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Xemu", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Xemu", "linux"),
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xemu")
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
                logger.log_error("Could not setup Xemu config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Xemu"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify Xemu system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Xemu"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Xemu", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Xemu system files")
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
            programs.get_emulator_program("Xemu"),
            "-dvd_path", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-full-screen"
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
