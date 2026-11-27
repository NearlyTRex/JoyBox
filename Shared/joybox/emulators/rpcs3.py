# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import archive
from joybox import emulatorcommon
from joybox import emulatorbase


# RPCS3 emulator
class RPCS3(emulatorbase.EmulatorBase):

    NAME = "RPCS3"

    # Download the Windows 7z and Linux AppImage from the RPCS3 rpcs3-binaries-win and -linux GitHub releases
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("RPCS3", "windows"):
            success = release.download_github_release(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-win",
                starts_with = "rpcs3",
                ends_with = "win64_msvc.7z",
                search_file = "rpcs3.exe",
                install_name = "RPCS3",
                install_dir = programs.get_program_install_dir("RPCS3", "windows"),
                backups_dir = programs.get_program_backup_dir("RPCS3", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RPCS3")
                return False

        # Download linux program
        if programs.should_program_be_installed("RPCS3", "linux"):
            success = release.download_github_release(
                github_user = "RPCS3",
                github_repo = "rpcs3-binaries-linux",
                starts_with = "rpcs3",
                ends_with = ".AppImage",
                install_name = "RPCS3",
                install_dir = programs.get_program_install_dir("RPCS3", "linux"),
                backups_dir = programs.get_program_backup_dir("RPCS3", "linux"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RPCS3")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("RPCS3", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RPCS3", "windows"),
                install_name = "RPCS3",
                install_dir = programs.get_program_install_dir("RPCS3", "windows"),
                search_file = "rpcs3.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RPCS3")
                return False

        # Setup linux program
        if programs.should_program_be_installed("RPCS3", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("RPCS3", "linux"),
                install_name = "RPCS3",
                install_dir = programs.get_program_install_dir("RPCS3", "linux"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup RPCS3")
                return False
        return True

    # Write its config files, verify the locker system files, then unzip the dev_flash archive
    # into each platform's setup dir, keeping files already there
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
                logger.log_error("Could not setup RPCS3 config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["dev_flash"]:
                if os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("RPCS3"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.extract_archive(
                        archive_file = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("RPCS3"), obj + config.ArchiveFileType.ZIP.cval()),
                        extract_dir = paths.join_paths(programs.get_emulator_path_config_value("RPCS3", "setup_dir", platform), obj),
                        skip_existing = True,
                        verbose = setup_params.verbose,
                        pretend_run = setup_params.pretend_run,
                        exit_on_failure = setup_params.exit_on_failure)
                    if not success:
                        logger.log_error("Could not extract RPCS3 system files")
                        return False
        return True

    # Copy PSN games' .rap and .edat files into the save exdata dir, then run RPCS3 on the game;
    # fullscreen also hides its GUI
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
        game_save_dir = game_info.get_save_dir()
        game_cache_dir = game_info.get_local_cache_dir()

        # Copy exdata files
        if game_platform == config.Platform.SONY_PLAYSTATION_NETWORK_PS3:
            for exdata_file in paths.build_file_list_by_extensions(game_cache_dir, extensions = [".rap", ".edat"]):
                filebulk.smart_copy(
                    src = exdata_file,
                    dest = paths.join_paths(game_save_dir, "exdata"),
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("RPCS3"),
            config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "--fullscreen",
                "--no-gui"
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
