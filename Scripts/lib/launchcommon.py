# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import cache
import system
import metadata
import environment
import gui

# Simple generic launcher
def SimpleLaunch(
    launch_cmd,
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_capture_type):

    # Get launch categories
    launch_supercategory, launch_category, launch_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)

    # Install game to cache
    cache.InstallGameToCache(
        game_platform = launch_platform,
        game_name = launch_name,
        game_file = launch_file,
        game_artwork = launch_artwork,
        verbose = config.default_flag_verbose)

    # Get cache dir
    cache_dir = environment.GetCachedRomDir(launch_category, launch_subcategory, launch_name)

    # Get json info
    json_file_path = environment.GetJsonRomMetadataFile(
        game_category = launch_category,
        game_subcategory = launch_subcategory,
        game_name = launch_name)
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Get json launch info
    json_launch_name = None
    json_launch_file = None
    if config.general_key_launch_name in json_file_data:
        json_launch_name = json_file_data[config.general_key_launch_name]
    if config.general_key_launch_file in json_file_data:
        json_launch_file = json_file_data[config.general_key_launch_file]

    # Selected launch file
    selected_launch_file = ""

    # Single choice
    if isinstance(json_launch_file, str):
        selected_launch_file = json_launch_file

    # More than one potential choice
    elif isinstance(json_launch_file, list):

        # Handle game selection
        def HandleGameSelection(selected_file):
            nonlocal selected_launch_file
            selected_launch_file = selected_file

        # Display choices
        gui.DisplayChoicesWindow(
            choice_list = json_launch_file,
            title_text = "Select Game",
            message_text = "Select game to run",
            button_text = "Run game",
            window_size = environment.GetCurrentScreenResolution(),
            run_func = HandleGameSelection)

    # Nothing to run
    if len(selected_launch_file) == 0 and not json_launch_name:
        return

    # Replace game tokens
    real_launch_cmd = []
    for cmd_segment in launch_cmd:

        # Replace game name
        if json_launch_name:
            cmd_segment = cmd_segment.replace(config.token_game_name, json_launch_name)

        # Replace game file
        if selected_launch_file:
            cmd_segment = cmd_segment.replace(config.token_game_file, os.path.join(cache_dir, selected_launch_file))

        # Replace game dir
        cmd_segment = cmd_segment.replace(config.token_game_dir, cache_dir)

        # Add segment
        real_launch_cmd += [cmd_segment]

    # Launch game
    cache.LaunchCachedGame(
        game_platform = launch_platform,
        game_name = launch_name,
        game_file = launch_file,
        launch_cmd = real_launch_cmd,
        capture_type = launch_capture_type,
        verbose = config.default_flag_verbose)
