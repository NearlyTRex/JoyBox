# Imports
import os
import sys

# Local imports
import config
import fileops
import system
import programs
import stores
import gui
import paths
from .installing import InstallStoreGame
from .installing import InstallLocalGame
from .saves import ImportStoreGameSave
from .saves import ExportStoreGameSave
from .saves import ImportLocalGameSave
from .saves import ExportLocalGameSave

###########################################################

# Launch store game
def LaunchStoreGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid() or not game_info.is_playable():
        return False

    # Install store game
    success = InstallStoreGame(
        game_info = game_info,
        source_type = source_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if store handles launching
    if not store_obj.CanHandleLaunching():
        return False

    # Get store info
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.GetInstallIdentifierKey()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)

    # Import save
    success = ImportStoreGameSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Launch game
    success = store_obj.Launch(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Export save
    success = ExportStoreGameSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Launch local game
def LaunchLocalGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid() or not game_info.is_playable():
        return False

    # Install local game
    success = InstallLocalGame(
        game_info = game_info,
        source_type = source_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Get launcher
    game_launcher = programs.GetEmulatorByPlatform(game_info.get_platform())
    if not game_launcher:
        gui.DisplayErrorPopup(
            title_text = "Launcher not found",
            message_text = "Launcher for game '%s' in platform '%s' could not be found" % (game_info.get_name(), game_info.get_platform()))
        return False

    # Get game launcher info
    game_launcher_config_file = game_launcher.GetConfigFile()
    game_launcher_save_dir = game_launcher.GetSaveDir(game_info.get_platform())
    game_launcher_setup_dir = game_launcher.GetSetupDir()

    # Import save
    success = ImportLocalGameSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Setup launcher save directory
    if paths.is_path_valid(game_launcher_save_dir):
        success = fileops.create_symlink(
            src = game_info.get_save_dir(),
            dest = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Setup launcher config file
    if paths.is_path_file(game_launcher_config_file):
        fileops.replace_strings_in_file(
            src = game_launcher_config_file,
            replacements = [
                {"from": config.token_emulator_setup_root, "to": game_launcher_setup_dir},
                {"from": config.token_game_save_dir, "to": game_info.get_save_dir()}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Launch game
    success = game_launcher.Launch(
        game_info = game_info,
        capture_type = capture_type,
        fullscreen = fullscreen,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Revert launcher config file
    if paths.is_path_file(game_launcher_config_file):
        fileops.replace_strings_in_file(
            src = game_launcher_config_file,
            replacements = [
                {"from": game_launcher_setup_dir, "to": config.token_emulator_setup_root},
                {"from": game_info.get_save_dir(), "to": config.token_game_save_dir}
            ],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Revert launcher save directory
    if paths.is_path_valid(game_launcher_save_dir):
        success = fileops.remove_object(
            obj = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = fileops.make_directory(
            src = game_launcher_save_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Export save
    success = ExportLocalGameSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Launch game
def LaunchGame(
    game_info,
    source_type,
    capture_type = None,
    fullscreen = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return LaunchStoreGame(
            game_info = game_info,
            source_type = source_type,
            capture_type = capture_type,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return LaunchLocalGame(
            game_info = game_info,
            source_type = source_type,
            capture_type = capture_type,
            fullscreen = fullscreen,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################
