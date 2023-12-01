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
def LaunchViaAres(
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_general_save_dir,
    launch_capture_type):

    # Get system types
    system_types = programs.GetEmulatorConfigValue("Ares", "save_sub_dirs")

    # Check if this platform is valid
    if not launch_platform in system_types:
        gui.DisplayErrorPopup(
            title_text = "Launch platform not defined",
            message_text = "Launch platform %s not defined in Ares config" % launch_platform)

    # Get launch command
    launch_cmd = [
        programs.GetEmulatorProgram("Ares"),
        "--system",
        system_types[launch_platform],
        "--fullscreen",
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
