# Local imports
from joybox import config
from joybox import environment
from joybox import filebulk
from joybox import logger
from joybox import paths
from joybox import programs
from joybox import gui
from joybox import emulatorcommon
from joybox import emulatorbase

# Ares's --system name for a platform, from its save_sub_dirs config; shows an error
# popup when the platform has none
def get_system_type(game_platform):

    # Get system types
    system_types = programs.get_emulator_config_value("Ares", "save_sub_dirs")

    # Check if this platform is valid
    if game_platform not in system_types:
        gui.display_error_popup(
            title_text = "Launch platform not defined",
            message_text = "Launch platform %s not defined in Ares config" % game_platform)
    return system_types[game_platform]

# Ares emulator
class Ares(emulatorbase.EmulatorBase):

    NAME = "Ares"

    # Write its config files, then verify the locker system files and copy them into each platform's setup dir
    def configure(self, setup_params = None):
        if not setup_params:
            setup_params = config.SetupParams()

        # Create config files
        if not self.write_config_files(setup_params):
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

        # Get system type
        system_type = get_system_type(game_info.get_platform())

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("Ares"),
            "--system",
            system_type,
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
