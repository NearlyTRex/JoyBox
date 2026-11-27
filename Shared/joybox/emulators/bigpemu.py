# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import logger
from joybox import paths
from joybox import release
from joybox import programs
from joybox import emulatorcommon
from joybox import emulatorbase


# BigPEmu emulator
class BigPEmu(emulatorbase.EmulatorBase):

    NAME = "BigPEmu"

    # Download the latest Windows zip linked from the richwhitehouse.com Jaguar download page; Windows only
    def setup(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Download windows program
        if programs.should_program_be_installed("BigPEmu", "windows"):
            success = release.download_webpage_release(
                webpage_url = "https://www.richwhitehouse.com/jaguar/index.php?content=download",
                webpage_base_url = "https://www.richwhitehouse.com",
                starts_with = "https://www.richwhitehouse.com/jaguar/builds/BigPEmu_v",
                ends_with = "[0-9].zip",
                search_file = "BigPEmu.exe",
                install_name = "BigPEmu",
                install_dir = programs.get_program_install_dir("BigPEmu", "windows"),
                backups_dir = programs.get_program_backup_dir("BigPEmu", "windows"),
                get_latest = True,
                locker_type = setup_params.locker_type,
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BigPEmu")
                return False
        return True

    # Install the Windows build from the release stored in its backups dir
    def setup_offline(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Setup windows program
        if programs.should_program_be_installed("BigPEmu", "windows"):
            success = release.setup_stored_release(
                archive_dir = programs.get_program_backup_dir("BigPEmu", "windows"),
                install_name = "BigPEmu",
                install_dir = programs.get_program_install_dir("BigPEmu", "windows"),
                search_file = "BigPEmu.exe",
                verbose = setup_params.verbose,
                pretend_run = setup_params.pretend_run,
                exit_on_failure = setup_params.exit_on_failure)
            if not success:
                logger.log_error("Could not setup BigPEmu")
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
                logger.log_error("Could not setup BigPEmu config files")
                return False
        return True

    # Run BigPEmu on the game file with -localdata so it keeps its data beside the program
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
            programs.get_emulator_program("BigPEmu"),
            config.TOKEN_GAME_FILE,
            "-localdata"
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
