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
from joybox import gameinfo
from joybox import prompts

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

# Install the game through its store client by its install identifier; False when the store does not handle installing
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


# Remove the game through its store client by its install identifier; False when the store does not handle installing
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

# Check the locker holds the game's ROM files, showing a popup when it does not
def _check_source_files(game_info, game_rom_dir, locker_type = None):
    if locker.does_path_contain_files(game_rom_dir, locker_type = locker_type):
        return True
    gui.display_error_popup(
        title_text = "Source files unavailable",
        message_text = "Source files are not available\n%s\n%s" % (game_info.get_name(), game_info.get_platform()))
    return False

# Install the downloaded files into the cache behind a loading window, transformed when the platform needs it
def _cache_game_from_dir(
    game_info,
    source_dir,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    game_platform = game_info.get_platform()
    game_label = "%s\n%s" % (game_info.get_name(), game_platform)

    # Check if transformation is required
    transform_required = platforms.is_transform_platform(game_platform)
    message_text = "Adding game to cache\n%s" % game_label
    if transform_required:
        message_text = "Transforming and adding game to cache\n%s" % game_label

    # Install game, transformed when required
    def install_cached_game():
        if transform_required:
            return install_local_transformed_game(
                game_info = game_info,
                source_dir = source_dir,
                keep_setup_files = keep_setup_files,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        return install_local_untransformed_game(
            game_info = game_info,
            source_dir = source_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    gui.display_loading_window(
        title_text = "Installing to cache",
        message_text = message_text,
        failure_text = "Unable to install game to cache",
        image_file = game_info.get_boxfront_asset(),
        run_func = install_cached_game)

# Check the cache now holds the game, showing a popup when it does not (a pretend run caches nothing)
def _check_game_cached(game_info, pretend_run = False):
    if not pretend_run and not is_local_game_installed(game_info):
        gui.display_error_popup(
            title_text = "Failed to cache game",
            message_text = "Game could not be cached\n%s\n%s" % (game_info.get_name(), game_info.get_platform()))
        return False
    return True

# Decrypt the ROM files into a temp dir, install them into the cache from there and check they landed
def _download_and_cache_game(
    game_info,
    game_rom_dir,
    locker_type = None,
    keep_setup_files = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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

        # Install files
        _cache_game_from_dir(
            game_info = game_info,
            source_dir = tmp_dir_result,
            keep_setup_files = keep_setup_files,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check if game is now installed
    return _check_game_cached(game_info, pretend_run = pretend_run)

# Decrypt the game's ROM files from one locker into a temp dir and copy them, transformed when the platform needs it, into the local cache
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

    # Check if already installed
    game_rom_dir = game_info.get_rom_dir(locker_type)
    if is_local_game_installed(game_info):
        return True

    # Check if source files are available
    if not _check_source_files(game_info, game_rom_dir, locker_type = locker_type):
        return False

    # Download and install game
    return _download_and_cache_game(
        game_info = game_info,
        game_rom_dir = game_rom_dir,
        locker_type = locker_type,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy the source dir's files into the game's local cache; True when the cache then holds files
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

# Hand the game's DLC and update folders from the locker to each emulator for its platform; True when the platform takes no addons
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

# Remove the game's local and remote cache dirs; True when it is not cached
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
    return is_local_game_installed(game_info)

# Install through the store client for store platforms, otherwise into the local cache from the locker
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
    return install_local_game(
        game_info = game_info,
        locker_type = locker_type,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Install a local game's DLC and updates into its emulators; store games pass, as their clients fetch add-ons
def install_game_addons(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        # Store clients fetch their own add-ons
        return True
    return install_local_game_addons(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Uninstall through the store client for store platforms, otherwise remove the local game's cache
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
    return uninstall_local_game(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# The JSON file of the ROMs game named by category, subcategory and name; None unless all three are given
def get_named_game_json_file(game_category = None, game_subcategory = None, game_name = None):
    if game_category and game_subcategory and game_name:
        return environment.get_game_json_metadata_file(
            game_supercategory = config.Supercategory.ROMS,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name)
    return None

# Quit through an error popup when no game JSON file was chosen or it is not a file
def check_game_json_file(json_file):
    if not json_file:
        gui.display_error_popup(
            title_text = "No json file specified",
            message_text = "No json file was specified")
    if not paths.is_path_file(json_file):
        gui.display_error_popup(
            title_text = "Json file not found",
            message_text = "Json file %s was not found" % json_file)

# Preview installing the game from its JSON file; False when the user declines
def _confirm_game_json_install(json_file, game_info, locker_type):
    details = [
        "JSON file: %s" % json_file,
        "Game: %s" % game_info.get_name(),
        "Source: %s" % locker_type
    ]
    if not prompts.prompt_for_preview("Install game", details):
        logger.log_warning("Operation cancelled by user")
        return False
    return True

# Install the game, then its addons when asked, quitting through an error popup at a failed step
def _install_game_and_addons(game_info, json_file, locker_type = None, keep_setup_files = False, install_addon_files = False, verbose = False, pretend_run = False, exit_on_failure = False):
    success = install_game(
        game_info = game_info,
        locker_type = locker_type,
        keep_setup_files = keep_setup_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        gui.display_error_popup(
            title_text = "Json file failed to install",
            message_text = "Json file '%s' failed to install" % paths.get_filename_file(json_file))
    if not install_addon_files:
        return
    success = install_game_addons(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        gui.display_error_popup(
            title_text = "Json file addons failed to install",
            message_text = "Json file '%s' addons failed to install" % paths.get_filename_file(json_file))

# After an optional preview, install the game of a JSON file, or of the one category, subcategory
# and name point to, into the local cache, then its addons when asked
def install_game_from_json(
    json_file = None,
    game_category = None,
    game_subcategory = None,
    game_name = None,
    locker_type = None,
    keep_setup_files = False,
    install_addon_files = False,
    show_preview = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not json_file:
        json_file = get_named_game_json_file(game_category, game_subcategory, game_name)
    check_game_json_file(json_file)
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if show_preview and not _confirm_game_json_install(json_file, game_info, locker_type):
        return
    _install_game_and_addons(
        game_info, json_file,
        locker_type = locker_type,
        keep_setup_files = keep_setup_files,
        install_addon_files = install_addon_files,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
