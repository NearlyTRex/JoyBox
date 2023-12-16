# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import gui
import environment
import metadata
import programs
import saves

# Launch game
def LaunchGame(game_platform, game_file, capture_type = None, fullscreen = False, verbose = False, exit_on_failure = False):

    # Get game categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(game_platform)

    # Get game name
    game_name = os.path.basename(os.path.dirname(game_file))

    # Get launcher
    game_launcher = None
    for emulator in programs.GetEmulators():
        if game_platform in emulator.GetPlatforms():
            game_launcher = emulator
            break

    # Check game launcher
    if not game_launcher:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (system.GetFilenameFile(game_file), game_platform))

    # Get game info
    game_artwork_file = environment.GetSyncedGameAssetFile(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        asset_type = config.asset_type_boxfront)
    game_config_file = game_launcher.GetConfigFile()
    game_save_format = game_launcher.GetSaveFormat()
    game_save_dir_launcher = game_launcher.GetSaveDir(game_platform)
    game_save_dir_real = environment.GetCachedSaveDir(game_category, game_subcategory, game_name, game_save_format)
    game_save_dir_general = environment.GetCachedSaveDir(game_category, game_subcategory, game_name, config.save_format_general)

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(game_category, game_subcategory, game_name):
        saves.UnpackSave(game_category, game_subcategory, game_name, verbose = verbose, exit_on_failure = exit_on_failure)

    # Make sure real save directory exists
    system.MakeDirectory(game_save_dir_real, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup save directory
    if game_save_dir_launcher:
        system.MakeDirectory(system.GetFilenameDirectory(game_save_dir_launcher), verbose = verbose, exit_on_failure = exit_on_failure)
        system.RemoveObject(game_save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)
        system.CreateSymlink(game_save_dir_real, game_save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup config file
    if game_config_file:
        system.ReplaceStringsInFile(
            src = game_config_file,
            replacements = [
                {"from": config.token_emulator_setup_root, "to": game_launcher.GetSetupDir()},
                {"from": config.token_emulator_main_root, "to": environment.GetEmulatorsRootDir()},
                {"from": config.token_game_save_dir, "to": game_save_dir_real}
            ],
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Launch game
    game_launcher.Launch(
        launch_name = game_name,
        launch_platform = game_platform,
        launch_file = game_file,
        launch_artwork = game_artwork_file,
        launch_save_dir = game_save_dir_real,
        launch_general_save_dir = game_save_dir_general,
        launch_capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Revert config file
    if game_config_file:
        system.ReplaceStringsInFile(
            src = game_config_file,
            replacements = [
                {"from": game_launcher.GetSetupDir(), "to": config.token_emulator_setup_root},
                {"from": environment.GetEmulatorsRootDir(), "to": config.token_emulator_main_root},
                {"from": game_save_dir_real, "to": config.token_game_save_dir}
            ],
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Revert save directory
    if game_save_dir_launcher:
        system.RemoveObject(game_save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)
        system.MakeDirectory(game_save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

    # Pack save
    saves.PackSave(game_category, game_subcategory, game_name, verbose = verbose, exit_on_failure = exit_on_failure)
