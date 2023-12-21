# Imports
import os, os.path
import sys

# Local imports
import config
import cache
import system
import metadata
import environment
import gameinfo
import gui

# Simple generic launcher
def SimpleLaunch(
    json_data,
    launch_cmd,
    launch_options = None,
    capture_type = None,
    verbose = False,
    exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_category = json_data[config.json_key_category]
    game_subcategory = json_data[config.json_key_subcategory]
    game_launch_name = json_data[config.json_key_launch_name]
    game_launch_file = json_data[config.json_key_launch_file]

    # Install game to cache
    cache.InstallGameToCache(
        json_data = json_data,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get cache dir
    cache_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)

    # Selected launch file
    selected_launch_file = ""

    # Single choice
    if isinstance(game_launch_file, list) and len(game_launch_file) == 1:
        selected_launch_file = game_launch_file[0]

    # More than one potential choice
    elif isinstance(game_launch_file, list) and len(game_launch_file) > 1:

        # Handle game selection
        def HandleGameSelection(selected_file):
            nonlocal selected_launch_file
            selected_launch_file = selected_file

        # Display choices
        gui.DisplayChoicesWindow(
            choice_list = game_launch_file,
            title_text = "Select Game",
            message_text = "Select game to run",
            button_text = "Run game",
            run_func = HandleGameSelection)

    # Nothing to run
    if len(selected_launch_file) == 0 and not game_launch_name:
        return

    # Replace game tokens
    real_launch_cmd = []
    for cmd_segment in launch_cmd:

        # Replace game name
        if game_launch_name:
            cmd_segment = cmd_segment.replace(config.token_game_name, game_launch_name)

        # Replace game file
        if selected_launch_file:
            cmd_segment = cmd_segment.replace(config.token_game_file, os.path.join(cache_dir, selected_launch_file))

        # Replace game dir
        cmd_segment = cmd_segment.replace(config.token_game_dir, cache_dir)

        # Add segment
        real_launch_cmd += [cmd_segment]

    # Launch game
    cache.LaunchCachedGame(
        json_data = json_data,
        launch_cmd = real_launch_cmd,
        launch_options = launch_options,
        capture_type = capture_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
