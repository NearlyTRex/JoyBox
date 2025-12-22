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
import nintendo
import paths
import gui
import emulatorcommon
import emulatorbase

# Config files
config_files = {}
config_files["Cemu/windows/settings.xml"] = ""
config_files["Cemu/windows/keys.txt"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"] = ""
config_files["Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"] = ""

# System files
system_files = {}

# Cemu emulator
class Cemu(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Cemu"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.NINTENDO_WII_U,
            config.Platform.NINTENDO_WII_U_ESHOP
        ]

    # Get config
    def get_config(self):
        return {
            "Cemu": {
                "program": {
                    "windows": "Cemu/windows/Cemu.exe",
                    "linux": "Cemu/linux/Cemu.AppImage"
                },
                "save_dir": {
                    "windows": "Cemu/windows/mlc01/usr/save/00050000",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/mlc01/usr/save/00050000"
                },
                "setup_dir": {
                    "windows": "Cemu/windows",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu"
                },
                "config_file": {
                    "windows": "Cemu/windows/settings.xml",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.config/Cemu/settings.xml"
                },
                "keys_file": {
                    "windows": "Cemu/windows/keys.txt",
                    "linux": "Cemu/linux/Cemu.AppImage.home/.local/share/Cemu/keys.txt"
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
                for tik_file in paths.build_file_list_by_extensions(package_dir, extensions = [".tik"]):
                    if tik_file.endswith("title.tik"):
                        tik_dir = paths.get_filename_directory(tik_file)
                        success = nintendo.InstallWiiUNusPackage(
                            nus_package_dir = tik_dir,
                            nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Cemu", "setup_dir"), "mlc01"),
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

        # Download windows program
        if programs.should_program_be_installed("Cemu", "windows"):
            success = release.DownloadGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "cemu",
                ends_with = "windows-x64.zip",
                search_file = "Cemu.exe",
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "windows"),
                backups_dir = programs.get_program_backup_dir("Cemu", "windows"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
                return False

        # Download linux program
        if programs.should_program_be_installed("Cemu", "linux"):
            success = release.DownloadGithubRelease(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "Cemu",
                ends_with = ".AppImage",
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "linux"),
                backups_dir = programs.get_program_backup_dir("Cemu", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Cemu", "windows"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Cemu", "windows"),
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "windows"),
                search_file = "Cemu.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Cemu", "linux"):
            success = release.SetupStoredRelease(
                archive_dir = programs.get_program_backup_dir("Cemu", "linux"),
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
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
                logger.log_error("Could not setup Cemu config files")
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

        # Get game info
        game_cache_dir = game_info.get_local_cache_dir()

        # Update keys
        for key_file in paths.build_file_list_by_extensions(game_cache_dir, extensions = [".txt"]):
            if key_file.endswith(".key.txt"):
                for platform in ["windows", "linux"]:
                    nintendo.UpdateWiiUKeys(
                        src_key_file = key_file,
                        dest_key_file = programs.get_emulator_path_config_value("Cemu", "keys_file", platform),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("Cemu"),
            "-g", config.token_game_file
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
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
