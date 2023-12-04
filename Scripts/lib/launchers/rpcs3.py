# Imports
import os
import os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(lib_folder)
import config
import cache
import programs
import metadata
import environment
import system
import launchcommon

# Launcher
def LaunchViaRPCS3(
    launch_name,
    launch_platform,
    launch_file,
    launch_artwork,
    launch_save_dir,
    launch_general_save_dir,
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

    # Get directories
    cache_dir = environment.GetCachedRomDir(launch_category, launch_subcategory, launch_name)
    exdata_dir = os.path.join(launch_save_dir, "exdata")

    # Make directories
    system.MakeDirectory(
        dir = exdata_dir,
        verbose = config.default_flag_verbose,
        exit_on_failure = config.default_flag_exit_on_failure)

    # Copy exdata files
    if launch_platform == "Sony PlayStation Network - PlayStation 3":
        for exdata_file in system.BuildFileListByExtensions(cache_dir, extensions = [".rap", ".edat"]):
            system.CopyFileOrDirectory(
                src = exdata_file,
                dest = exdata_dir,
                verbose = config.default_flag_verbose)

    # Get launch command
    launch_cmd = [
        programs.GetEmulatorProgram("RPCS3"),
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
