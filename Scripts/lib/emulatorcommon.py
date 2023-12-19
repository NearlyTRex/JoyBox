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
    launch_cmd,
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_capture_type,
    verbose = False,
    exit_on_failure = False):

    # Get launch categories
    launch_supercategory, launch_category, launch_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)

    # Install game to cache
    cache.InstallGameToCache(
        game_platform = launch_platform,
        game_name = launch_name,
        game_file = launch_file,
        game_artwork = launch_artwork,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get cache dir
    cache_dir = environment.GetCachedRomDir(launch_category, launch_subcategory, launch_name)

    # Get json info
    json_data = gameinfo.ParseGameJson(launch_file, verbose = verbose, exit_on_failure = exit_on_failure)
    json_launch_name = json_data[config.json_key_launch_name]
    json_launch_file = json_data[config.json_key_launch_file]

    # Selected launch file
    selected_launch_file = ""

    # Single choice
    if isinstance(json_launch_file, list) and len(json_launch_file) == 1:
        selected_launch_file = json_launch_file[0]

    # More than one potential choice
    elif isinstance(json_launch_file, list) and len(json_launch_file) > 1:

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
        verbose = verbose,
        exit_on_failure = exit_on_failure)