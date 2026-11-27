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


# FSUAE emulator
class FSUAE(emulatorbase.EmulatorBase):

    NAME = "FS-UAE"

    # Windows build from the FrodeSolheim/fs-uae GitHub release; Linux AppImage built from
    # the 3.1.66 source tarball, with fs-uae.dat beside it
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("FS-UAE", "windows"):
            success = release.download_github_release(
                github_user = "FrodeSolheim",
                github_repo = "fs-uae",
                starts_with = "FS-UAE",
                ends_with = "Windows_x86-64.zip",
                search_file = "Plugin.ini",
                install_name = "FS-UAE",
                install_dir = programs.get_program_install_dir("FS-UAE", "windows"),
                backups_dir = programs.get_program_backup_dir("FS-UAE", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
                return False

        # Build linux program
        if programs.should_program_be_installed("FS-UAE", "linux"):
            success = sourcebuild.build_appimage_from_source(
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
                    {"from": "Source/fs-uae-3.1.66/fs-uae-3.1.66/fs-uae", "to": "AppImage/usr/bin/fs-uae"},
                    {"from": "Source/fs-uae-3.1.66/fs-uae-3.1.66/share/applications/fs-uae.desktop", "to": "AppImage/app.desktop"},
                    {"from": "Source/fs-uae-3.1.66/fs-uae-3.1.66/share/icons/hicolor/256x256/apps/fs-uae.png", "to": "AppImage/fs-uae.png"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/fs-uae", "to": "AppRun"}
                ],
                external_copies = [
                    {"from": "Source/fs-uae-3.1.66/fs-uae-3.1.66/fs-uae.dat", "to": "fs-uae.dat"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup FS-UAE")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("FS-UAE", "windows"):
            success = release.setup_stored_release(
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
            success = release.setup_stored_release(
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
                logger.log_error("Could not setup FS-UAE config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("FS-UAE"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("FS-UAE", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup FS-UAE system files")
                    return False
        return True

    # Run FS-UAE on the game file, with --fullscreen=1 when asked
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
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen=1"
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
