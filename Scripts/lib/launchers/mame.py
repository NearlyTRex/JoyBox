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
def LaunchViaMame(
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_general_save_dir,
    launch_capture_type):

    # Get launch command
    launch_cmd = [programs.GetEmulatorProgram("Mame")]

    # Add ini path
    launch_cmd += [
        "-inipath",
        programs.GetEmulatorPathConfigValue("Mame", "config_dir")
    ]

    # Add rom path
    if launch_platform == "Arcade":
        launch_cmd += [
            "-rompath",
            config.token_game_dir
        ]
    else:
        launch_cmd += [
            "-rompath",
            programs.GetEmulatorPathConfigValue("Mame", "roms_dir")
        ]

    # Add launch file
    if launch_platform == "Arcade":
        launch_cmd += [
            config.token_game_name
        ]
    elif launch_platform == "Atari 5200":
        launch_cmd += [
            "a5200",
            "-cart",
            config.token_game_file
        ]
    elif launch_platform == "Atari 7800":
        launch_cmd += [
            "a7800",
            "-cart",
            config.token_game_file
        ]
    elif launch_platform == "Magnavox Odyssey 2":
        launch_cmd += [
            "odyssey2",
            "-cart",
            config.token_game_file
        ]
    elif launch_platform == "Mattel Intellivision":
        launch_cmd += [
            "intv",
            "-cart",
            config.token_game_file
        ]
    elif launch_platform == "Philips CDi":
        launch_cmd += [
            "cdimono1",
            "-cdrom",
            config.token_game_file
        ]
    elif launch_platform == "Texas Instruments TI-99-4A":
        launch_cmd += [
            "ti99_4a",
            "-cart",
            config.token_game_file
        ]
    elif launch_platform == "Tiger Game.com":
        launch_cmd += [
            "gamecom",
            "-cart1",
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