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
def LaunchGame(json_data, capture_type = None, fullscreen = False, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = json_data[config.json_key_base_name]
    game_category = json_data[config.json_key_category]
    game_subcategory = json_data[config.json_key_subcategory]
    game_platform = json_data[config.json_key_platform]

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
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (game_name, game_platform))

    # Get game info
    game_config_file = game_launcher.GetConfigFile()
    game_save_type = game_launcher.GetSaveType()
    game_save_dir_launcher = game_launcher.GetSaveDir(game_platform)
    game_save_dir_real = environment.GetCachedSaveDir(game_category, game_subcategory, game_name, game_save_type)
    game_save_dir_general = environment.GetCachedSaveDir(game_category, game_subcategory, game_name, config.save_type_general)

    # Set save dirs
    json_data[config.json_key_save_dir] = game_save_dir_real
    json_data[config.json_key_general_save_dir] = game_save_dir_general

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
        json_data = json_data,
        capture_type = capture_type,
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
