# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import release
from joybox import programs
from joybox.nintendo import wiiu
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase


# Cemu emulator
class Cemu(emulatorbase.EmulatorBase):

    NAME = "Cemu"

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        dlc_dirs = [] if dlc_dirs is None else dlc_dirs
        update_dirs = [] if update_dirs is None else update_dirs
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for tik_file in paths.build_file_list_by_extensions(package_dir, extensions = [".tik"]):
                    if tik_file.endswith("title.tik"):
                        tik_dir = paths.get_filename_directory(tik_file)
                        success = wiiu.install_wiiu_nus_package(
                            nus_package_dir = tik_dir,
                            nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Cemu", "setup_dir"), "mlc01"),
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        if not success:
                            return False
        return True

    # Download the Windows zip and Linux AppImage from the cemu-project GitHub release
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("Cemu", "windows"):
            success = release.download_github_release(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "cemu",
                ends_with = "windows-x64.zip",
                search_file = "Cemu.exe",
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "windows"),
                backups_dir = programs.get_program_backup_dir("Cemu", "windows"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
                return False

        # Download linux program
        if programs.should_program_be_installed("Cemu", "linux"):
            success = release.download_github_release(
                github_user = "cemu-project",
                github_repo = "Cemu",
                starts_with = "Cemu",
                ends_with = ".AppImage",
                install_name = "Cemu",
                install_dir = programs.get_program_install_dir("Cemu", "linux"),
                backups_dir = programs.get_program_backup_dir("Cemu", "linux"),
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Cemu")
                return False
        return True

    # Install the Windows and Linux builds from the releases stored in their backups dirs
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("Cemu", "windows"):
            success = release.setup_stored_release(
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
            success = release.setup_stored_release(
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
                logger.log_error("Could not setup Cemu config files")
                return False
        return True

    # Merge the game's .key.txt files into each platform's keys file, then run Cemu with -g on the game
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
                    success = wiiu.update_wiiu_keys(
                        src_key_file = key_file,
                        dest_key_file = programs.get_emulator_path_config_value("Cemu", "keys_file", platform),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        logger.log_error("Could not update Cemu keys from %s" % key_file)
                        return False

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("Cemu"),
            "-g", config.TOKEN_GAME_FILE
        ]
        if fullscreen:
            launch_cmd += [
                "-f"
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
