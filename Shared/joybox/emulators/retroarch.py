# Imports
import os
import os.path

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

# The core file its cores_mapping names for the platform; shows an error popup when the
# platform has no core or the core file is missing
def get_core_file(game_platform):

    # Get core info
    cores_dir = programs.get_emulator_path_config_value("RetroArch", "cores_dir")
    cores_ext = programs.get_emulator_config_value("RetroArch", "cores_ext")
    cores_mapping = programs.get_emulator_config_value("RetroArch", "cores_mapping")

    # Check if this platform is valid
    if game_platform not in cores_mapping:
        gui.display_error_popup(
            title_text = "Launch platform not defined",
            message_text = "Launch platform %s not defined in RetroArch config" % game_platform)

    # Check if core is installed
    core_file = paths.join_paths(cores_dir, cores_mapping[game_platform] + cores_ext)
    if not os.path.exists(core_file):
        gui.display_error_popup(
            title_text = "RetroArch core not found",
            message_text = "RetroArch core '%s' could not be found!" % cores_mapping[game_platform])
    return core_file

# RetroArch emulator
class RetroArch(emulatorbase.EmulatorBase):

    NAME = "RetroArch"

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
                    src = paths.join_paths(environment.get_locker_gaming_emulator_setup_dir("RetroArch"), filename),
                    dest = paths.join_paths(programs.get_emulator_path_config_value("RetroArch", "setup_dir", platform), filename),
                    verbose = setup_params.verbose,
                    pretend_run = setup_params.pretend_run,
                    exit_on_failure = setup_params.exit_on_failure)
                if not success:
                    logger.log_error("Could not setup RetroArch system files")
                    return False
        return True

    # Run RetroArch with -L on the core its cores_mapping names for the platform;
    # quits with an error popup when the platform has no core or the core file is missing
    def launch(
        self,
        game_info,
        capture_type = None,
        capture_file = None,
        fullscreen = False,
        verbose = False,
        pretend_run = False,
        exit_on_failure = False):

        # Get core file
        core_file = get_core_file(game_info.get_platform())

        # Get launch command
        launch_cmd = [
            programs.get_emulator_program("RetroArch"),
            "-L", core_file,
            config.TOKEN_GAME_FILE
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
