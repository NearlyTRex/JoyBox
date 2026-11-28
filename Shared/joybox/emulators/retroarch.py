# Imports
import os
import os.path

# Local imports
from joybox import paths
from joybox import programs
from joybox import gui
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

    # The core file its cores_mapping names for the game's platform, for the {core_file} launch argument
    def get_launch_values(self, game_info):
        return {"core_file": get_core_file(game_info.get_platform())}
