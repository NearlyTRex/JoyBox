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
import gui

# Check if game file is in cache already
def IsGameInCache(game_platform, game_name):
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)
    game_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)
    if not os.path.exists(game_dir):
        return False
    if system.IsDirectoryEmpty(game_dir):
        return False
    return True

# Remove game from cache
def RemoveGameFromCache(game_platform, game_name, game_file, verbose = False, exit_on_failure = False):

    # Ignore if not in cache
    if not IsGameInCache(game_platform, game_namea):
        return

    # Get categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get directories
    cached_rom_dir = environment.GetCachedRomDir(game_category, game_subcategory, game_name)
    cached_install_dir = environment.GetInstallRomDir(game_category, game_subcategory, game_name)

    # Remove directories
    system.RemoveDirectory(cached_rom_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    system.RemoveDirectory(cached_install_dir, verbose = verbose, exit_on_failure = exit_on_failure)

# Install game to cache
def InstallGameToCache(game_platform, game_name, game_file, game_artwork, keep_setup_files = False, verbose = False, exit_on_failure = False):

    # Check if already installed
    if IsGameInCache(game_platform, game_name):
        return

    # Get categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get json info
    json_file_data = system.ReadJsonFile(game_file, verbose = verbose, exit_on_failure = exit_on_failure)
    json_launch_name = None
    if config.general_key_launch_name in json_file_data:
        json_launch_name = json_file_data[config.general_key_launch_name]
    json_launch_file = None
    if config.general_key_launch_file in json_file_data:
        json_launch_file = json_file_data[config.general_key_launch_file]
    json_transform_file = None
    if config.general_key_transform_file in json_file_data:
        json_transform_file = json_file_data[config.general_key_transform_file]

    # Get source info
    source_dir = environment.GetRomDir(game_category, game_subcategory, game_name)
    source_file = ""
    if json_launch_file:
        source_file = os.path.join(source_dir, json_launch_file)
    if json_transform_file:
        source_file = os.path.join(source_dir, json_transform_file)
    if json_launch_name and len(source_file) == 0:
        source_file = os.path.join(source_dir, json_launch_name)

    # Check if source files are available
    if json_launch_name and source_file.endswith(json_launch_name):
        if not os.path.isdir(source_dir):
            gui.DisplayErrorPopup(
                title_text = "Source dir unavailable",
                message_text = "Source dir is not available\n%s\n%s" % (game_name, game_platform))
    else:
        if not os.path.isfile(source_file):
            gui.DisplayErrorPopup(
                title_text = "Source file unavailable",
                message_text = "Source file is not available\n%s\n%s" % (game_name, game_platform))

    # Check if transformation is required
    if platforms.AreTransformsRequired(game_platform):

        # Install transformed game
        def InstallTransformedGame():
            return AddTransformedGameToCache(
                game_platform = game_platform,
                game_name = game_name,
                game_file = source_file,
                json_file = game_file,
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
                game_platform = game_platform,
                game_name = game_name,
                game_file = source_file,
                json_file = game_file,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
        gui.DisplayLoadingWindow(
            title_text = "Installing to cache",
            message_text = "Adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallGame)

    # Check if game is now installed
    if not IsGameInCache(game_platform, game_name):
        gui.DisplayErrorPopup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))

# Add game to cache
def AddGameToCache(game_platform, game_name, game_file, json_file, verbose = False, exit_on_failure = False):

    # Get categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get directories
    source_dir = system.GetFilenameDirectory(game_file)
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
            game_platform = game_platform,
            game_name = game_name,
            json_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Return result
    return IsGameInCache(
        game_platform = game_platform,
        game_name = game_name)

# Add transformed game to cache
def AddTransformedGameToCache(game_platform, game_name, game_file, json_file, keep_setup_files = False, verbose = False, exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Transform game file
    transform_success, transform_result = transform.TransformGameFile(
        game_platform = game_platform,
        game_name = game_name,
        source_game_file = game_file,
        source_json_file = json_file,
        output_dir = tmp_dir_result,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Add to cache
    if transform_success:
        AddGameToCache(
            game_platform = game_platform,
            game_name = game_name,
            game_file = transform_result,
            json_file = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Return result
    return IsGameInCache(
        game_platform = game_platform,
        game_name = game_name)

# Launch cached game
def LaunchCachedGame(
    game_platform,
    game_name,
    game_file,
    launch_cmd,
    launch_options = None,
    capture_type = None,
    verbose = False,
    exit_on_failure = False):

    # Check if already cached
    if not IsGameInCache(game_platform, game_name):
        return

    # Get game categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Launch game
    command.RunGameCommand(
        category = game_category,
        subcategory = game_subcategory,
        name = game_name,
        cmd = launch_cmd,
        options = launch_options,
        capture_type = capture_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
