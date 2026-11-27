# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import gui
from joybox import emulatorcommon
from joybox import emulatorbase


# Ares emulator
class Ares(emulatorbase.EmulatorBase):

    NAME = "Ares"

    # Windows build from the ares-emulator GitHub release; Linux AppImage built from the NearlyTRex/Ares fork
    # with CMake, its Database and Firmware copied into the AppImage home
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Ares", "windows"):
            success = release.download_github_release(
                github_user = "ares-emulator",
                github_repo = "ares",
                starts_with = "ares",
                ends_with = "windows-x64.zip",
                search_file = "ares.exe",
                install_name = "Ares",
                install_dir = programs.get_program_install_dir("Ares", "windows"),
                backups_dir = programs.get_program_backup_dir("Ares", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ares")
                return False

        # Download linux program
        if programs.should_program_be_installed("Ares", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Ares.git",
                output_file = "ares-x86_64.AppImage",
                install_name = "Ares",
                install_dir = programs.get_program_install_dir("Ares", "linux"),
                backups_dir = programs.get_program_backup_dir("Ares", "linux"),
                build_cmd = [
                    "cmake", "-B", "build", "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
                    "&&",
                    "cmake", "--build", "build"
                ],
                internal_copies = [
                    {"from": "Source/Ares/build/rundir/bin/ares", "to": "AppImage/usr/bin/ares"},
                    {"from": "Source/Ares/desktop-ui/resource/ares.desktop", "to": "AppImage/ares.desktop"},
                    {"from": "Source/Ares/desktop-ui/resource/ares.png", "to": "AppImage/ares.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/ares", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/Ares/mia/Database", "to": "Ares.AppImage.home/.local/share/ares/Database"},
                    {"from": "Source/Ares/mia/Firmware", "to": "Ares.AppImage.home/.local/share/ares/Firmware"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ares")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Ares", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ares", "windows"),
                install_name = "Ares",
                install_dir = programs.get_program_install_dir("Ares", "windows"),
                search_file = "ares.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ares")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Ares", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Ares", "linux"),
                install_name = "Ares",
                install_dir = programs.get_program_install_dir("Ares", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ares")
                return False
        return True

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        for config_filename, config_contents in self.get_config_files().items():
            success = fileops.touch_file(
                src = paths.join_paths(environment.get_emulators_root_dir(), config_filename),
                contents = config_contents.strip(),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Ares config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Ares"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Ares", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Ares system files")
                    return False
        return True

    # Run Ares with --system set from the platform's save_sub_dirs entry; quits with an error popup when it has none
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
        game_platform = game_info.get_platform()

        # Get system types
        system_types = programs.get_emulator_config_value("Ares", "save_sub_dirs")

        # Check if this platform is valid
        if game_platform not in system_types:
            gui.display_error_popup(
                title_text = "Launch platform not defined",
                message_text = "Launch platform %s not defined in Ares config" % game_platform)

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("Ares"),
            "--system",
            system_types[game_platform],
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen"
            ]

        # Launch game
        return emulatorcommon.simple_launch(
            game_info = game_info,
            launch_cmd = launch_cmd,
            capture_type = capture_type,
            capture_file = capture_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
