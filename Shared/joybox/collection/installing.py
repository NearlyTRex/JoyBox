# Local imports
from joybox import emulators
from joybox import config
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import transform
from joybox import platforms
from joybox import locker
from joybox import stores
from joybox import gui

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


# Uninstall store game
def uninstall_store_game(
    game_info,
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

    # Installing reads from one locker
    if locker_type == config.LockerType.ALL:
        logger.log_error("Installing reads from one locker; choose one instead of %s" % locker_type)
        return False

    # Get game info
    game_name = game_info.get_name()
    game_platform = game_info.get_platform()
    game_artwork = game_info.get_boxfront_asset()
    game_rom_dir = game_info.get_rom_dir(locker_type)

    # Check if already installed
    if is_local_game_installed(game_info):
        return True

    # Check if source files are available
    if not locker.does_path_contain_files(game_rom_dir, locker_type = locker_type):
        gui.display_error_popup(
            title_text = "Source files unavailable",
            message_text = "Source files are not available\n%s\n%s" % (game_name, game_platform))
        return False

    # Download into a temporary directory and install from there
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            return False

        # Download files
        success, _ = locker.sync_from_remote_decrypted(
            src = game_rom_dir,
            dest = tmp_dir_result,
            locker_type = locker_type,
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
                run_func = install_transformed_game)
        else:

            # Install game
            def install_untransformed_game():
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
                run_func = install_untransformed_game)

    # Check if game is now installed (a pretend run caches nothing)
    if not pretend_run and not is_local_game_installed(game_info):
        gui.display_error_popup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_name, game_platform))
        return False
    return True

# Install local untransformed game
def install_local_untransformed_game(
    game_info,
    source_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy game files
    success = filebulk.copy_contents(
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

    # Transform game file into a temporary directory and add it to the cache
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir_result:
        if not tmp_dir_result:
            return False
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
        return install_local_untransformed_game(
            game_info = game_info,
            source_dir = paths.get_filename_directory(transform_result),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

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
    for filename in game_info.get_value(config.JSON_KEY_DLC) or []:
        source_dlc_dirs += [paths.join_paths(environment.get_locker_gaming_dlc_root_dir(), filename)]
    for filename in game_info.get_value(config.JSON_KEY_UPDATE) or []:
        source_update_dirs += [paths.join_paths(environment.get_locker_gaming_update_root_dir(), filename)]

    # Install add-ons
    for emulator in emulators.get_emulator_list():
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
        # Store clients fetch their own add-ons
        return True
    else:
        return install_local_game_addons(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Uninstall game
def uninstall_game(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return uninstall_store_game(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return uninstall_local_game(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################
