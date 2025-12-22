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
[config]
amiga_model = A500
governor_warning = 0
"""
config_files["FS-UAE/windows/Portable.ini"] = ""
config_files["FS-UAE/windows/Configurations/Default.fs-uae"] = config_file_general
config_files["FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"] = config_file_general

# System files
system_files = {}
system_files["Kickstarts/kick40068.A1200"] = "646773759326fbac3b2311fd8c8793ee"
system_files["Kickstarts/kick34005.A500"] = "82a21c1890cae844b3df741f2762d48d"
system_files["Kickstarts/kick40063.A600"] = "e40a5dfb3d017ba8779faba30cbd1c8e"

# FSUAE emulator
class FSUAE(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "FS-UAE"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.OTHER_COMMODORE_AMIGA
        ]

    # Get config
    def get_config(self):
        return {
            "FS-UAE": {
                "program": {
                    "windows": "FS-UAE/windows/Windows/x86-64/fs-uae.exe",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage"
                },
                "save_dir": {
                    "windows": None,
                    "linux": None
                },
                "setup_dir": {
                    "windows": "FS-UAE/windows",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE"
                },
                "config_file": {
                    "windows": "FS-UAE/windows/Configurations/Default.fs-uae",
                    "linux": "FS-UAE/linux/FS-UAE.AppImage.home/FS-UAE/Configurations/Default.fs-uae"
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
        if programs.should_program_be_installed("FS-UAE", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "FrodeSolheim",
                github_repo = "fs-uae",
                starts_with = "FS-UAE",
                ends_with = "Windows_x86-64.zip",
                search_file = "Plugin.ini",
                install_name = "FS-UAE",
                install_dir = programs.get_program_install_dir("FS-UAE", "windows"),
                backups_dir = programs.get_program_backup_dir("FS-UAE", "windows"),
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
                return False

        # Build linux program
        if programs.should_program_be_installed("FS-UAE", "linux"):
            success = release.BuildAppImageFromSource(
                release_url = "https://github.com/FrodeSolheim/fs-uae/releases/download/v3.1.66/fs-uae-3.1.66.tar.xz",
                output_file = "FS-UAE-x86_64.AppImage",
                install_name = "FS-UAE",
                install_dir = programs.get_program_install_dir("FS-UAE", "linux"),
                backups_dir = programs.get_program_backup_dir("FS-UAE", "linux"),
                build_cmd = [
                    "cd", "fs-uae-3.1.66",
                    "&&",
                    "./configure",
                    "&&",
                    "make", "-j", "8"
                ],
                internal_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                    {"from": "Source/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/fs-uae", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("FS-UAE", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("FS-UAE", "windows"),
                install_name = "FS-UAE",
                install_dir = programs.get_program_install_dir("FS-UAE", "windows"),
                search_file = "Plugin.ini",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
                return False

        # Setup linux program
        if programs.should_program_be_installed("FS-UAE", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("FS-UAE", "linux"),
                install_name = "FS-UAE",
                install_dir = programs.get_program_install_dir("FS-UAE", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
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
                logger.log_error("Could not setup FS-UAE config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("FS-UAE"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify FS-UAE system file %s" % filename)
                return False

        # Copy system files
        for filename in system_files.keys():
            for platform in ["windows", "linux"]:
                success = fileops.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("FS-UAE"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("FS-UAE", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup FS-UAE system files")
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
            programs.get_emulator_program("FS-UAE"),
            config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=1"
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
