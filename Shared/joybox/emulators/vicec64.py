# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import release
from joybox import sourcebuild
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# ViceC64 emulator
class ViceC64(emulatorbase.EmulatorBase):

    NAME = "VICE-C64"

    # Windows SDL2 build from the VICE-Team/svn-mirror GitHub release; Linux AppImage of x64sc
    # built from the NearlyTRex/ViceC64 fork with autotools
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("VICE-C64", "windows"):
            success = release.download_github_release(
                github_user = "VICE-Team",
                github_repo = "svn-mirror",
                starts_with = "SDL2VICE",
                ends_with = "win64.zip",
                search_file = "x64sc.exe",
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "windows"),
                backups_dir = programs.get_program_backup_dir("VICE-C64", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False

        # Download linux program
        if programs.should_program_be_installed("VICE-C64", "linux"):
            success = sourcebuild.build_appimage_from_source(
                release_url = "https://github.com/NearlyTRex/ViceC64.git",
                output_file = "App-x86_64.AppImage",
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "linux"),
                backups_dir = programs.get_program_backup_dir("VICE-C64", "linux"),
                build_cmd = [
                    "cd", "vice",
                    "&&",
                    "./autogen.sh",
                    "&&",
                    "./configure", "--disable-html-docs", "--enable-pdf-docs=no",
                    "&&",
                    "make", "-j", "4"
                ],
                internal_copies = [
                    {"from": "Source/ViceC64/vice/data", "to": "AppImage/usr/bin"},
                    {"from": "Source/ViceC64/vice/src/x64sc", "to": "AppImage/usr/bin/x64sc"},
                    {"from": "AppImageTool/linux/app.desktop", "to": "AppImage/app.desktop"},
                    {"from": "AppImageTool/linux/icon.svg", "to": "AppImage/icon.svg"}
                ],
                internal_symlinks = [
                    {"from": "usr/bin/x64sc", "to": "AppRun"}
                ],
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("VICE-C64", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("VICE-C64", "windows"),
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "windows"),
                search_file = "x64sc.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False

        # Setup linux program
        if programs.should_program_be_installed("VICE-C64", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("VICE-C64", "linux"),
                install_name = "VICE-C64",
                install_dir = programs.get_program_install_dir("VICE-C64", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup VICE-C64")
                return False
        return True

    # Write its config files under the emulators root
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
                logger.log_error("Could not setup VICE-C64 config files")
                return False
        return True

    # Run the x64sc emulator on the game file
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
            programs.get_emulator_program("VICE-C64"),
            config.TOKEN_GAME_FILE
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
