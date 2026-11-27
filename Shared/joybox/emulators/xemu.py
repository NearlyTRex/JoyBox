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
from joybox import emulatorcommon
from joybox import emulatorbase


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

    # Setup
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Xemu", "windows"):
            success = release.download_github_release(
                github_user = "mborgerson",
                github_repo = "xemu",
                starts_with = "xemu",
                ends_with = "win-x86_64-release.zip",
                search_file = "xemu.exe",
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "windows"),
                backups_dir = programs.get_program_backup_dir("Xemu", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Xemu")
                return False

        # Build linux program
        if programs.should_program_be_installed("Xemu", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/Xemu.git",
                output_file = "xemu-x86_64.AppImage",
                install_name = "Xemu",
                install_dir = programs.get_program_install_dir("Xemu", "linux"),
                backups_dir = programs.get_program_backup_dir("Xemu", "linux"),
                build_cmd = [
                    "./build.sh"
                ],
                internal_copies = [
                    {"from": "Source/Xemu/dist/xemu", "to": "AppImage/usr/bin/xemu"},
                    {"from": "Source/Xemu/ui/xemu.desktop", "to": "AppImage/xemu.desktop"},
                    {"from": "Source/Xemu/ui/icons/xemu.svg", "to": "AppImage/xemu.svg"}
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
            success = release.setup_stored_release(
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
            success = release.setup_stored_release(
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
        for config_filename, config_contents in self.get_config_files().items():
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
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
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
            "-dvd_path", config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "-full-screen"
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
