# Imports
import os, os.path
import sys

# Local imports
import config
import command
import environment
import system
import metadata
import transform
import addon
import platforms
import gameinfo
import gui

# Check if game file is in cache already
def IsGameInCache(json_data):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_category = json_data[config.json_key_category]
    game_subcategory = json_data[config.json_key_subcategory]

    # Get cache dir
    cache_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)

    # Non-existent cache dir
    if not os.path.exists(cache_dir):
        return False

    # Empty cache dir
    if system.IsDirectoryEmpty(cache_dir):
        return False

    # Should be in cache
    return True

# Remove game from cache
def RemoveGameFromCache(json_data, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_category = json_data[config.json_key_category]
    game_subcategory = json_data[config.json_key_subcategory]

    # Ignore if not in cache
    if not IsGameInCache(json_data):
        return

    # Get directories
    cached_rom_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)
    cached_install_dir = environment.GetInstallRomDir(game_category, game_subcategory, game_name)

    # Remove directories
    system.RemoveDirectory(cached_rom_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.RemoveDirectory(cached_install_dir, verbose = verbose, exit_on_failure = exit_on_failure)

# Install game to cache
def InstallGameToCache(json_data, keep_setup_files = False, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_platform = json_data[config.json_key_platform]
    game_artwork = json_data[config.json_key_artwork]
    game_source_file = json_data[config.json_key_source_file]
    game_source_dir = json_data[config.json_key_source_dir]

    # Check if already installed
    if IsGameInCache(json_data):
        return

    # Check if source files are available
    files_available = False
    if len(game_source_file) and os.path.isfile(game_source_file):
        files_available = True
    elif len(game_source_dir) and os.path.isdir(game_source_dir):
        files_available = True
    if not files_available:
        gui.DisplayErrorPopup(
            title_text = "Source files unavailable",
            message_text = "Source files are not available\n%s\n%s" % (game_name, game_platform))

    # Check if transformation is required
    if platforms.AreTransformsRequired(game_platform):

        # Install transformed game
        def InstallTransformedGame():
            return AddTransformedGameToCache(
                json_data = json_data,
                source_file = game_source_file,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
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
                json_data = json_data,
                source_file = game_source_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallGame)

    # Check if game is now installed
    if not IsGameInCache(json_data):
        gui.DisplayErrorPopup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))

# Add game to cache
def AddGameToCache(json_data, source_file, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_category = json_data[config.json_key_category]
    game_subcategory = json_data[config.json_key_subcategory]
    game_platform = json_data[config.json_key_platform]

    # Get directories
    source_dir = system.GetFilenameDirectory(source_file)
    dest_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)

    # Make directories
    system.MakeDirectory(dest_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Copy game files
    system.CopyContents(
        src = source_dir,
        dest = dest_dir,
        show_progress = True,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Install addons
    if platforms.AreAddonsPossible(game_platform):
        addon.InstallAddons(
            json_data = json_data,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Return result
    return IsGameInCache(json_data)

# Add transformed game to cache
def AddTransformedGameToCache(json_data, source_file, keep_setup_files = False, verbose = False, exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Transform game file
    transform_success, transform_result = transform.TransformGameFile(
        json_data = json_data,
        source_file = source_file,
        output_dir = tmp_dir_result,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Add to cache
    if transform_success:
        AddGameToCache(
            json_data = json_data,
            source_file = transform_result,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Return result
    return IsGameInCache(json_data)

# Launch cached game
def LaunchCachedGame(
    json_data,
    launch_cmd,
    launch_options = None,
    capture_type = None,
    verbose = False,
    exit_on_failure = False):

    # Check if already cached
    if not IsGameInCache(json_data):
        return

    # Launch game
    command.RunGameCommand(
        json_data = json_data,
        cmd = launch_cmd,
        options = launch_options,
        capture_type = capture_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
