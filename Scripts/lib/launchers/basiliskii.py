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

# Launcher
def LaunchViaBasiliskII(
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_general_save_dir,
    launch_capture_type):

    # Get launch command
    launch_cmd = [
        programs.GetEmulatorProgram("BasiliskII"),
        "--disk",
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
