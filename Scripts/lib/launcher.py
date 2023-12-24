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
def LaunchGame(game_info, capture_type = None, fullscreen = False, verbose = False, exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_category = game_info.get_category()
    game_subcategory = game_info.get_subcategory()
    game_platform = game_info.get_platform()
    game_save_dir = game_info.get_save_dir()

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

    # Get game launcher info
    game_launcher_config_file = game_launcher.GetConfigFile()
    game_launcher_save_dir = game_launcher.GetSaveDir(game_platform)
    game_launcher_setup_dir = game_launcher.GetSetupDir()

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(game_category, game_subcategory, game_name):
        saves.UnpackSave(game_category, game_subcategory, game_name, verbose = verbose, exit_on_failure = exit_on_failure)

    # Make sure real save directory exists
    system.MakeDirectory(game_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup save directory
    if game_launcher_save_dir:
        system.MakeDirectory(system.GetFilenameDirectory(game_launcher_save_dir), verbose = verbose, exit_on_failure = exit_on_failure)
        system.RemoveObject(game_launcher_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)
        system.CreateSymlink(game_save_dir, game_launcher_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup config file
    if game_launcher_config_file:
        system.ReplaceStringsInFile(
            src = game_launcher_config_file,
            replacements = [
                {"from": config.token_emulator_setup_root, "to": game_launcher_setup_dir},
                {"from": config.token_game_save_dir, "to": game_save_dir}
            ],
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Launch game
    game_launcher.Launch(
        game_info = game_info,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Revert config file
    if game_launcher_config_file:
        system.ReplaceStringsInFile(
            src = game_launcher_config_file,
            replacements = [
                {"from": game_launcher_setup_dir, "to": config.token_emulator_setup_root},
                {"from": game_save_dir, "to": config.token_game_save_dir}
            ],
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Revert save directory
    if game_launcher_save_dir:
        system.RemoveObject(game_launcher_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)
        system.MakeDirectory(game_launcher_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Pack save
    saves.PackSave(game_category, game_subcategory, game_name, verbose = verbose, exit_on_failure = exit_on_failure)
