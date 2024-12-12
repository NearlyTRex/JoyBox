# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import transform
import platforms
import gameinfo
import locker
import gui

# Check if game file is in cache already
def IsGameInCache(game_info):
    cache_dir = game_info.get_local_cache_dir()
    return system.DoesDirectoryContainFiles(cache_dir)

# Remove game from cache
def RemoveGameFromCache(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Ignore if not in cache
    if not IsGameInCache(game_info):
        return

    # Remove directories
    system.RemoveDirectory(
        dir = game_info.get_local_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.RemoveDirectory(
        dir = game_info.get_remote_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Install game to cache
def InstallGameToCache(
    game_info,
    source_type,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_platform = game_info.get_platform()
    game_artwork = game_info.get_boxfront_asset()
    game_rom_dir = game_info.get_rom_dir(source_type)

    # Check if already installed
    if IsGameInCache(game_info):
        return

    # Check if source files are available
    if not system.DoesDirectoryContainFiles(game_rom_dir):
        gui.DisplayErrorPopup(
            title_text = "Source files unavailable",
            message_text = "Source files are not available\n%s\n%s" % (game_name, game_platform))

    # Check if transformation is required
    if platforms.IsTransformPlatform(game_platform):

        # Install transformed game
        def InstallTransformedGame():
            return AddTransformedGameToCache(
                game_info = game_info,
                source_dir = game_rom_dir,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Transforming and adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallTransformedGame)
    else:

        # Install game
        def InstallGame():
            return AddGameToCache(
                game_info = game_info,
                source_dir = game_rom_dir,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallGame)

    # Check if game is now installed
    if not IsGameInCache(game_info):
        gui.DisplayErrorPopup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))

# Add game to cache
def AddGameToCache(
    game_info,
    source_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy game files
    success = system.CopyContents(
        src = source_dir,
        dest = game_info.get_local_cache_dir(),
        show_progress = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Return result
    return IsGameInCache(game_info)

# Add transformed game to cache
def AddTransformedGameToCache(
    game_info,
    source_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Transform game file
    transform_success, transform_result = transform.TransformGameFile(
        game_info = game_info,
        source_dir = source_dir,
        output_dir = tmp_dir_result,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not transform_success:
        system.LogError(transform_result)
        return False

    # Add to cache
    AddGameToCache(
        game_info = game_info,
        source_dir = system.GetFilenameDirectory(transform_result),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return result
    return IsGameInCache(game_info)

# Launch cached game
def LaunchCachedGame(
    game_info,
    launch_cmd,
    launch_options = None,
    capture_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if already cached
    if not IsGameInCache(game_info):
        return

    # Launch game
    command.RunGameCommand(
        game_info = game_info,
        cmd = launch_cmd,
        options = launch_options,
        capture_type = capture_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
