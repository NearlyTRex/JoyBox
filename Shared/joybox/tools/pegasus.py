# Local imports
from joybox import config
from joybox import logger
from joybox import network
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import environment
from joybox import fileops
from joybox import toolbase
from joybox import desktopentry


# Pegasus tool
class Pegasus(toolbase.ToolBase):

    NAME = "Pegasus"

    # Windows build from the mmatyas/pegasus-frontend GitHub release; Linux AppImage built from the
    # NearlyTRex/Pegasus fork with qmake; each also clones the PegasusThemeGrid theme
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
                github_branch = programs.get_tool_config_value("Pegasus", "theme_github_branch"),
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
            success = sourcebuild.build_appimage_from_source(
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
                    {"from": "Source/Pegasus/Build/src/app/pegasus-fe", "to": "AppImage/usr/bin/pegasus-fe"},
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
                github_branch = programs.get_tool_config_value("Pegasus", "theme_github_branch"),
                output_dir = paths.join_paths(programs.get_tool_path_config_value("Pegasus", "themes_dir", "linux"), "PegasusThemeGrid"),
                clean = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Pegasus theme")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
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
                install_files = ["pegasus-fe.exe"],
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

    # Write its config files with game_dirs.txt listing every dir that holds a metadata.pegasus.txt,
    # then add its app menu entry
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Generate game dirs
        game_dirs = []
        for pegasus_file in paths.build_file_list_by_extensions(environment.get_game_pegasus_metadata_root_dir(), extensions = [".txt"]):
            if pegasus_file.endswith("metadata.pegasus.txt"):
                game_dirs.append(paths.get_filename_directory(pegasus_file))

        # Update game dir files
        config_files = self.get_config_files()
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

        # Put it in the app menu
        success = desktopentry.set_launcher(
            enabled = True,
            filename = "joybox-pegasus.desktop",
            name = "Pegasus",
            description = "Browse and launch the game collection",
            command = "launch_pegasus",
            icon = "applications-games",
            verbose = setup_params.verbose,
            pretend_run = setup_params.pretend_run,
            exit_on_failure = setup_params.exit_on_failure)
        if not success:
            logger.log_error("Could not setup the Pegasus launcher")
            return False
        return True
