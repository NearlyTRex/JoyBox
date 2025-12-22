# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import fileops
import system
import logger
import release
import programs
import hashing
import archive
import nintendo
import paths
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_file_general = """
[Data%20Storage]
nand_directory=EMULATOR_SETUP_ROOT/nand/
sdmc_directory=EMULATOR_SETUP_ROOT/sdmc/

[UI]
Paths\screenshotPath=EMULATOR_SETUP_ROOT/screenshots/
"""
config_files["Citra/windows/user/config/qt-config.ini"] = config_file_general
config_files["Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"] = config_file_general

# System files
system_files = {}
system_files["nand.zip"] = "7c9baaa35b620bbd2b18b4620e2831e1"
system_files["sysdata.zip"] = "dcfa1fbaf7845c735b2c7d1ec9df2ed7"

# Citra emulator
class Citra(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Citra"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.NINTENDO_3DS,
            config.Platform.NINTENDO_3DS_APPS,
            config.Platform.NINTENDO_3DS_ESHOP
        ]

    # Get config
    def get_config(self):
        return {
            "Citra": {
                "program": {
                    "windows": "Citra/windows/citra-qt.exe",
                    "linux": "Citra/linux/citra-qt.AppImage"
                },
                "save_dir": {
                    "windows": "Citra/windows/user/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu/sdmc/Nintendo 3DS/00000000000000000000000000000000/00000000000000000000000000000000/title/00040000"
                },
                "setup_dir": {
                    "windows": "Citra/windows/user",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.local/share/citra-emu"
                },
                "config_file": {
                    "windows": "Citra/windows/user/config/qt-config.ini",
                    "linux": "Citra/linux/citra-qt.AppImage.home/.config/citra-emu/qt-config.ini"
                },
                "run_sandboxed": {
                    "windows": False,
                    "linux": False
                }
            }
        }

    # Install add-ons
    def install_addons(self, dlc_dirs = [], update_dirs = [], verbose = False, pretend_run = False, exit_on_failure = False):
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for cia_file in paths.build_file_list_by_extensions(package_dir, extensions = [".cia"]):
                    success = nintendo.Install3DSCIA(
                        src_3ds_file = cia_file,
                        sdmc_dir = paths.join_paths(programs.get_emulator_path_config_value("Citra", "setup_dir"), "sdmc"),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False
        return True

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Citra", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Citra", "windows"),
                install_name = "Citra",
                install_dir = programs.get_program_install_dir("Citra", "windows"),
                search_file = "citra-qt.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Citra")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Citra", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Citra", "linux"),
                install_name = "Citra",
                install_dir = programs.get_program_install_dir("Citra", "linux"),
                search_file = "citra-qt.AppImage",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Citra")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()
        self.setup(setup_params = setup_params)

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
                logger.log_error("Could not setup Citra config files")
                return False

        # Verify system files
        for filename, expected_md5 in system_files.items():
            actual_md5 = hashing.CalculateFileMD5(
                src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Citra"), filename),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            success = (expected_md5 == actual_md5)
            if not success:
                logger.log_error("Could not verify Citra system file %s" % filename)
                return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["nand", "sysdata"]:
                if os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Citra"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.ExtractArchive(
                        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Citra"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("Citra", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not extract Citra system files")
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
            programs.get_emulator_program("Citra"),
            config.token_game_file
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
