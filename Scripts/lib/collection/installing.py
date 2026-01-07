# Imports
import os
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import programs
import transform
import platforms
import locker
import stores
import gui

###########################################################

# Check if store game is installed
def is_store_game_installed(game_info):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if store handles installing
    if not store_obj.can_handle_installing():
        return False

    # Check store install
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.get_install_identifier_key()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.is_installed(store_identifier)

# Install store game
def install_store_game(
    game_info,
    locker_type = None,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if store handles installing
    if not store_obj.can_handle_installing():
        return False

    # Install game
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.get_install_identifier_key()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.install(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Install store game addons
def install_store_game_addons(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Not needed
    return True

# Uninstall store game
def uninstall_store_game(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check game info
    if not game_info or not game_info.is_valid():
        return False

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if store handles installing
    if not store_obj.can_handle_installing():
        return False

    # Uninstall game
    store_key = game_info.get_main_store_key()
    store_identifier_key = store_obj.get_install_identifier_key()
    store_identifier = game_info.get_subvalue(store_key, store_identifier_key)
    return store_obj.uninstall(
        identifier = store_identifier,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Check if local game is installed
def is_local_game_installed(game_info):
    cache_dir = game_info.get_local_cache_dir()
    return paths.does_directory_contain_files(cache_dir)

# Install local game
def install_local_game(
    game_info,
    locker_type = None,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_name = game_info.get_name()
    game_platform = game_info.get_platform()
    game_artwork = game_info.get_boxfront_asset()
    game_remote_rom_dir = game_info.get_remote_rom_dir()

    # Check if already installed
    if is_local_game_installed(game_info):
        return True

    # Check if source files are available
    if not locker.does_path_contain_files(game_remote_rom_dir):
        gui.display_error_popup(
            title_text = "Source files unavailable",
            message_text = "Source files are not available\n%s\n%s" % (game_name, game_platform))
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Download files
    success = locker.sync_from_remote_decrypted(
        src = game_remote_rom_dir,
        dest = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check if transformation is required
    if platforms.is_transform_platform(game_platform):

        # Install transformed game
        def install_transformed_game():
            return install_local_transformed_game(
                game_info = game_info,
                source_dir = tmp_dir_result,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.display_loading_window(
            title_text = "Installing to cache",
            message_text = "Transforming and adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallTransformedGame)
    else:

        # Install game
        def install_game():
            return install_local_untransformed_game(
                game_info = game_info,
                source_dir = tmp_dir_result,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        gui.display_loading_window(
            title_text = "Installing to cache",
            message_text = "Adding game to cache\n%s\n%s" % (game_name, game_platform),
            failure_text = "Unable to install game to cache",
            image_file = game_artwork,
            run_func = InstallGame)

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if game is now installed
    if not is_local_game_installed(game_info):
        gui.display_error_popup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))
    return True

# Install local untransformed game
def install_local_untransformed_game(
    game_info,
    source_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy game files
    success = fileops.copy_contents(
        src = source_dir,
        dest = game_info.get_local_cache_dir(),
        show_progress = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Return result
    return is_local_game_installed(game_info)

# Add local transformed game
def install_local_transformed_game(
    game_info,
    source_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Transform game file
    transform_success, transform_result = transform.transform_game_file(
        game_info = game_info,
        source_dir = source_dir,
        output_dir = tmp_dir_result,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not transform_success:
        logger.log_error(transform_result)
        return False

    # Add to cache
    success = install_local_untransformed_game(
        game_info = game_info,
        source_dir = paths.get_filename_directory(transform_result),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Return result
    return is_local_game_installed(game_info)

# Install local game addons
def install_local_game_addons(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game info
    game_platform = game_info.get_platform()

    # No addon possible
    if not platforms.are_addons_possible(game_platform):
        return True

    # Get directories
    source_dlc_dirs = []
    source_update_dirs = []
    for filename in game_info.get_value(config.json_key_dlc):
        source_dlc_dirs += [paths.join_paths(environment.get_locker_gaming_dlc_root_dir(), filename)]
    for filename in game_info.get_value(config.json_key_update):
        source_update_dirs += [paths.join_paths(environment.get_locker_gaming_update_root_dir(), filename)]

    # Install add-ons
    for emulator in programs.get_emulators():
        if game_platform in emulator.get_platforms():
            success = emulator.install_addons(
                dlc_dirs = source_dlc_dirs,
                update_dirs = source_update_dirs,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Should be successful
    return True

# Uninstall local game
def uninstall_local_game(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if already installed
    if not is_local_game_installed(game_info):
        return True

    # Remove local cache
    success = fileops.remove_directory(
        src = game_info.get_local_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Remove remote cache
    success = fileops.remove_directory(
        src = game_info.get_remote_cache_dir(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################

# Check if game is installed
def is_game_installed(game_info):
    if stores.is_store_platform(game_info.get_platform()):
        return is_store_game_installed(game_info)
    else:
        return is_local_game_installed(game_info)

# Install game
def install_game(
    game_info,
    locker_type = None,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return install_store_game(
            game_info = game_info,
            locker_type = locker_type,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return install_local_game(
            game_info = game_info,
            locker_type = locker_type,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Install game addons
def install_game_addons(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return install_store_game_addons(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return install_local_game_addons(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Uninstall game
def uninstall_game(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return uninstall_store_game(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return uninstall_local_game(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################
