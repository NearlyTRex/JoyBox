# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import metadata
import programs
import gameinfo
import saves
import gui

# Launch game
def LaunchGame(json_file, capture_type = None, fullscreen = False, verbose = False, exit_on_failure = False):

    # Get json info
    json_data = gameinfo.ParseGameJson(json_file, verbose = verbose, exit_on_failure = exit_on_failure)
    json_base_name = json_data[config.json_key_base_name]
    json_category = json_data[config.json_key_category]
    json_subcategory = json_data[config.json_key_subcategory]
    json_platform = json_data[config.json_key_platform]

    # Get launcher
    game_launcher = None
    for emulator in programs.GetEmulators():
        if json_platform in emulator.GetPlatforms():
            game_launcher = emulator
            break

    # Check game launcher
    if not game_launcher:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (json_base_name, json_platform))

    # Get game info
    game_artwork_file = environment.GetSyncedGameAssetFile(
        game_category = json_category,
        game_subcategory = json_subcategory,
        game_name = json_base_name,
        asset_type = config.asset_type_boxfront)
    game_config_file = game_launcher.GetConfigFile()
    game_save_type = game_launcher.GetSaveType()
    game_save_dir_launcher = game_launcher.GetSaveDir(json_platform)
    game_save_dir_real = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name, game_save_type)
    game_save_dir_general = environment.GetCachedSaveDir(json_category, json_subcategory, json_base_name, config.save_type_general)

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(json_category, json_subcategory, json_base_name):
        saves.UnpackSave(json_category, json_subcategory, json_base_name, verbose = verbose, exit_on_failure = exit_on_failure)

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
        launch_name = json_base_name,
        launch_platform = json_platform,
        launch_file = json_file,
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
    saves.PackSave(json_category, json_subcategory, json_base_name, verbose = verbose, exit_on_failure = exit_on_failure)
