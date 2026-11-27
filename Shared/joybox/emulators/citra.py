# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import release
from joybox import programs
from joybox import archive
from joybox.nintendo import threeds
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase


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

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        dlc_dirs = [] if dlc_dirs is None else dlc_dirs
        update_dirs = [] if update_dirs is None else update_dirs
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for cia_file in paths.build_file_list_by_extensions(package_dir, extensions = [".cia"]):
                    success = threeds.install_3ds_cia(
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
                skip_if_missing = True,
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
                skip_if_missing = True,
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
        return self.setup(setup_params = setup_params)

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
                logger.log_error("Could not setup Citra config files")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Extract system files
        for platform in ["windows", "linux"]:
            for obj in ["nand", "sysdata"]:
                if os.path.exists(paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Citra"), obj + config.ArchiveFileType.ZIP.cval())):
                    success = archive.extract_archive(
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
