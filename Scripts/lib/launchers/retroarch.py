# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import programs
import launchcommon
import gui

# Launcher
def LaunchViaRetroArch(
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_general_save_dir,
    launch_capture_type):

    # Get core info
    cores_dir = programs.GetEmulatorPathConfigValue("RetroArch", "cores_dir")
    cores_ext = programs.GetEmulatorConfigValue("RetroArch", "cores_ext")
    cores_mapping = programs.GetEmulatorConfigValue("RetroArch", "cores_mapping")

    # Check if this platform is valid
    if not launch_platform in cores_mapping:
        gui.DisplayErrorPopup(
            title_text = "Launch platform not defined",
            message_text = "Launch platform %s not defined in RetroArch config" % launch_platform)

    # Check if core is installed
    core_file = os.path.join(cores_dir, cores_mapping[launch_platform] + cores_ext)
    if not os.path.exists(core_file):
        gui.DisplayErrorPopup(
            title_text = "RetroArch core not found",
            message_text = "RetroArch core '%s' could not be found!" % cores_mapping[launch_platform])

    # Get launch command
    launch_cmd = [
        programs.GetEmulatorProgram("RetroArch"),
        "-L",
        os.path.join(cores_dir, cores_mapping[launch_platform] + cores_ext),
        config.token_game_file
    ]

    # Launch game
    launchcommon.SimpleLaunch(
        launch_cmd = launch_cmd,
        launch_name = launch_name,
        launch_platform = launch_platform,
        launch_file = launch_file,
        launch_artwork = launch_artwork,
        launch_save_dir = launch_save_dir,
        launch_capture_type = launch_capture_type)
