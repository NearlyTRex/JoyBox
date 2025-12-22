# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import network
import paths
import release
import programs
import environment
import fileops
import toolbase

# Config files
config_files = {}
config_file_general = """
general.theme: themes/PegasusThemeGrid/
general.verify-files: false
general.input-mouse-support: true
general.fullscreen: true
providers.steam.enabled: false
providers.gog.enabled: false
providers.es2.enabled: false
providers.launchbox.enabled: false
providers.logiqx.enabled: false
providers.playnite.enabled: false
providers.skraper.enabled: false
keys.menu: F1,GamepadStart
keys.page-down: PgDown,GamepadR2
keys.prev-page: Q,A,GamepadL1
keys.next-page: E,D,GamepadR1
keys.filters: F,GamepadY
keys.details: I,GamepadX
keys.cancel: Esc,Backspace,GamepadB
keys.page-up: PgUp,GamepadL2
keys.accept: Return,Enter,GamepadA
"""
config_files["Pegasus/windows/portable.txt"] = ""
config_files["Pegasus/windows/config/game_dirs.txt"] = ""
config_files["Pegasus/windows/config/settings.txt"] = config_file_general
config_files["Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/game_dirs.txt"] = ""
config_files["Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/settings.txt"] = config_file_general

# Pegasus tool
class Pegasus(toolbase.ToolBase):

    # Get name
    def get_name(self):
        return "Pegasus"

    # Get config
    def get_config(self):
        return {
            "Pegasus": {
                "program": {
                    "windows": "Pegasus/windows/pegasus-fe.exe",
                    "linux": "Pegasus/linux/Pegasus.AppImage"
                },
                "themes_dir": {
                    "windows": "Pegasus/windows/config/themes",
                    "linux": "Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/themes"
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
        if programs.should_program_be_installed("Pegasus", "windows"):
            success = release.download_github_release(
                github_user = "mmatyas",
                github_repo = "pegasus-frontend",
                starts_with = "pegasus-fe",
                ends_with = "win-mingw-static.zip",
                search_file = "pegasus-fe.exe",
                install_name = "Pegasus",
                install_dir = programs.get_program_install_dir("Pegasus", "windows"),
                backups_dir = programs.get_program_backup_dir("Pegasus", "windows"),
                install_files = ["pegasus-fe.exe"],
                get_latest = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus")
                return False
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PegasusThemeGrid",
                output_dir = paths.join_paths(programs.get_tool_path_config_value("Pegasus", "themes_dir", "windows"), "PegasusThemeGrid"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus theme")
                return False

        # Build linux program
        if programs.should_program_be_installed("Pegasus", "linux"):
            success = release.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Pegasus.git",
                output_file = "App-x86_64.AppImage",
                install_name = "Pegasus",
                install_dir = programs.get_program_install_dir("Pegasus", "linux"),
                backups_dir = programs.get_program_backup_dir("Pegasus", "linux"),
                build_cmd = [
                    "qmake", "..", "CONFIG+=release", "USE_SDL_GAMEPAD=1",
                    "&&",
                    "make", "-j", "4"
                ],
                build_dir = "Build",
                internal_copies = [
                    {"from": "Source/Build/src/app/pegasus-fe", "to": "AppImage/usr/bin/pegasus-fe"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/pegasus-fe", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus")
                return False
            success = network.download_github_repository(
                github_user = "NearlyTRex",
                github_repo = "PegasusThemeGrid",
                output_dir = paths.join_paths(programs.get_tool_path_config_value("Pegasus", "themes_dir", "linux"), "PegasusThemeGrid"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus theme")
                return False
        return True

    # Setup offline
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Pegasus", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Pegasus", "windows"),
                install_name = "Pegasus",
                install_dir = programs.get_program_install_dir("Pegasus", "windows"),
                search_file = "pegasus-fe.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Pegasus", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Pegasus", "linux"),
                install_name = "Pegasus",
                install_dir = programs.get_program_install_dir("Pegasus", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus")
                return False
        return True

    # Configure
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Generate game dirs
        game_dirs = []
        for pegasus_file in paths.build_file_list_by_extensions(environment.get_game_pegasus_metadata_root_dir(), extensions = [".txt"]):
            if pegasus_file.endswith("metadata.pegasus.txt"):
                game_dirs.append(paths.get_filename_directory(pegasus_file))

        # Update game dir files
        config_files["Pegasus/windows/config/game_dirs.txt"] = "\n".join(game_dirs)
        config_files["Pegasus/linux/Pegasus.AppImage.home/.config/pegasus-frontend/game_dirs.txt"] = "\n".join(game_dirs)

        # Create config files
        for config_filename, config_contents in config_files.items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_tools_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus config files")
                return False
        return True
