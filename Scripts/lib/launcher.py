# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import system
import gui
import environment
import metadata
import programs
import saves

# Launch game
def LaunchGame(launch_platform, file_path, capture_type = None, verbose = False, exit_on_failure = False):

    # Get real file path
    real_file_path = system.ResolveVirtualRomPath(file_path)
    if system.IsVirtualRomPath(real_file_path) or not system.IsPathValid(real_file_path):
        gui.DisplayErrorPopup(
            title_text = "Unable to resolve game file",
            message_text = "Game file '%s' could not be resolved" % file_path)

    # Get game categories
    game_supercategory, game_category, game_subcategory = metadata.DeriveMetadataCategoriesFromPlatform(launch_platform)

    # Get launch name
    launch_name = os.path.basename(os.path.dirname(real_file_path))

    # Get launcher
    game_launcher = None
    for emulator in programs.GetEmulators():
        if launch_platform in emulator.GetPlatforms():
            game_launcher = emulator
            break

    # Check game launcher
    if not game_launcher:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (system.GetFilenameFile(real_file_path), launch_platform))

    # Get launch artwork
    launch_artwork = environment.GetSyncedGameAssetFile(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = launch_name,
        asset_type = config.asset_type_boxfront)

    # Get save directories
    save_dir_launcher = game_launcher.GetSaveDir()
    save_dir_real = environment.GetCachedSaveDir(game_category, game_subcategory, launch_name, game_launcher.GetSaveFormat())
    save_dir_general = environment.GetCachedSaveDir(game_category, game_subcategory, launch_name, config.save_format_general)

    # Unpack save if possible
    if saves.CanSaveBeUnpacked(game_category, game_subcategory, launch_name):
        saves.UnpackSave(game_category, game_subcategory, launch_name, verbose = verbose, exit_on_failure = exit_on_failure)

    # Make sure save directory exists
    system.MakeDirectory(save_dir_real, verbose = verbose, exit_on_failure = exit_on_failure)

    # Setup launcher save directory
    if save_dir_launcher:

        # Make parent folder
        system.MakeDirectory(system.GetFilenameDirectory(save_dir_launcher), verbose = verbose, exit_on_failure = exit_on_failure)

        # Removing existing folder/symlink
        system.RemoveObject(save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

        # Create save symlink
        system.CreateSymlink(save_dir_real, save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

    # Replace tokens in config file
    system.ReplaceStringsInFile(
        src = game_launcher.GetConfigFile(),
        replacements = [
            {"from": config.token_emulator_main_root, "to": environment.GetEmulatorsRootDir()},
            {"from": config.token_game_save_dir, "to": save_dir_real}
        ],
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Launch game
    game_launcher.Launch(
        launch_name = launch_name,
        launch_platform = launch_platform,
        launch_file = real_file_path,
        launch_artwork = launch_artwork,
        launch_save_dir = save_dir_real,
        launch_general_save_dir = save_dir_general,
        launch_capture_type = capture_type)

    # Revert to tokens in config file
    system.ReplaceStringsInFile(
        src = game_launcher.GetConfigFile(),
        replacements = [
            {"from": environment.GetEmulatorsRootDir(), "to": config.token_emulator_main_root},
            {"from": save_dir_real, "to": config.token_game_save_dir}
        ],
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean launcher save directory
    if save_dir_launcher:

        # Removing existing symlink
        system.RemoveObject(save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

        # Create save folder
        system.MakeDirectory(save_dir_launcher, verbose = verbose, exit_on_failure = exit_on_failure)

    # Pack save
    saves.PackSave(game_category, game_subcategory, launch_name, verbose = verbose, exit_on_failure = exit_on_failure)
