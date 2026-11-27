# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import logger
from joybox import release
from joybox import programs
from joybox.nintendo import switch
from joybox import paths
from joybox import emulatorcommon
from joybox import emulatorbase


# Yuzu emulator
class Yuzu(emulatorbase.EmulatorBase):

    # Get name
    def get_name(self):
        return "Yuzu"

    # Get platforms
    def get_platforms(self):
        return [
            config.Platform.NINTENDO_SWITCH,
            config.Platform.NINTENDO_SWITCH_ESHOP
        ]

    # Install add-ons
    def install_addons(self, dlc_dirs = None, update_dirs = None, verbose = False, pretend_run = False, exit_on_failure = False):
        dlc_dirs = [] if dlc_dirs is None else dlc_dirs
        update_dirs = [] if update_dirs is None else update_dirs
        for package_dirset in [dlc_dirs, update_dirs]:
            for package_dir in package_dirset:
                for nsp_file in paths.build_file_list_by_extensions(package_dir, extensions = [".nsp"]):
                    success = switch.install_switch_nsp(
                        nsp_file = nsp_file,
                        nand_dir = paths.join_paths(programs.get_emulator_path_config_value("Yuzu", "setup_dir"), "nand"),
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
        if programs.should_program_be_installed("Yuzu", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Yuzu", "windows"),
                install_name = "Yuzu",
                install_dir = programs.get_program_install_dir("Yuzu", "windows"),
                preferred_archive = "Windows-Yuzu-EA-4176",
                search_file = "yuzu.exe",
                skip_if_missing = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Yuzu")
                return False

        # Setup linux program
        if programs.should_program_be_installed("Yuzu", "linux"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("Yuzu", "linux"),
                install_name = "Yuzu",
                install_dir = programs.get_program_install_dir("Yuzu", "linux"),
                preferred_archive = "Linux-Yuzu-EA-4176",
                skip_if_missing = True,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Yuzu")
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
                logger.log_error("Could not setup Yuzu config files")
                return False

        # Create profiles
        for platform in ["windows", "linux"]:
            success = switch.create_switch_profiles_dat(
                profiles_file = programs.get_emulator_path_config_value("Yuzu", "profiles_file", platform),
                user_id = programs.get_emulator_config_value("Yuzu", "profile_user_id"),
                account_name = programs.get_emulator_config_value("Yuzu", "profile_account_name"),
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup Yuzu profiles")
                return False

        # Verify system files
        if not self.verify_system_files(self.get_system_files(), setup_params):
            return False

        # Copy system files
        for filename in self.get_system_files().keys():
            for platform in ["windows", "linux"]:
                success = filebulk.smart_copy(
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("Yuzu"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("Yuzu", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup Yuzu system files")
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
            programs.get_emulator_program("Yuzu"),
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
