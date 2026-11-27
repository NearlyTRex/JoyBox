# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import environment
from joybox import fileops
from joybox import gamecollection
from joybox import gameinfo
from joybox import gamenaming
from joybox import cryption
from joybox import stores
from joybox import strings
from joybox import jsondata
from joybox import lockerinfo
from joybox import playlist

############################################################

# Determine if game json files are possible
def are_game_json_file_possible(
    game_supercategory):
    return game_supercategory in [config.Supercategory.ROMS, config.Supercategory.DLC, config.Supercategory.UPDATES]

############################################################

# Load the game's JSON metadata file as a JsonData for its platform; None when the supercategory has none or the file is missing
def read_game_json_data(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    verbose = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory):
        return None

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if not paths.does_path_exist(json_file_path):
        return None

    # Read json data
    json_file_data = serialization.read_json_file(
        src = json_file_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Get platform
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)

    # Return json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)
    return json_obj

############################################################

# Make the json file's directory and write the json data into it
def write_new_json_file(
    json_file_path,
    json_obj,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create json directory
    success = fileops.make_directory(
        src = paths.get_filename_directory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Write json file
    success = serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Write the game's JSON file from the initial data; True without writing when it exists or the supercategory takes none
def create_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    initial_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory):
        return True

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    if paths.does_path_exist(json_file_path):
        return True

    # Get platform
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)

    # Build json data
    json_file_data = {}
    if isinstance(initial_data, dict):
        json_file_data = initial_data

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Write json file
    return write_new_json_file(
        json_file_path = json_file_path,
        json_obj = json_obj,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Json keys whose files sit under a same-named folder of a ROM game's root
_ROM_SUBFILE_KEYS = (
    config.JSON_KEY_DLC,
    config.JSON_KEY_UPDATE,
    config.JSON_KEY_EXTRA,
    config.JSON_KEY_DEPENDENCIES)

# Read the game's json file into a JsonData for its platform, empty for a dry run that did not create it; None when missing otherwise
def read_game_json_obj(
    json_file_path,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check json file
    json_file_exists = paths.does_path_exist(json_file_path)
    if not json_file_exists and not pretend_run:
        return None

    # Read json data, or start from the empty file a dry run did not create
    json_file_data = {}
    if json_file_exists:
        json_file_data = serialization.read_json_file(
            src = json_file_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Create json data object
    return jsondata.JsonData(
        json_data = json_file_data,
        json_platform = gamenaming.derive_game_platform_from_categories(game_subcategory))

# Files under the game root relative to it, naming encrypted ones by their embedded name when readable
def list_game_root_files(
    game_root,
    locker_type = None,
    verbose = False,
    exit_on_failure = False):

    # Get passphrase
    passphrase = lockerinfo.LockerInfo(locker_type).get_passphrase()

    # Get all files
    all_files = paths.build_file_list(game_root)
    if cryption.is_passphrase_valid(passphrase):
        all_files = cryption.get_real_file_paths(
            src = all_files,
            passphrase = passphrase,
            verbose = verbose,
            exit_on_failure = exit_on_failure)

    # Get rebased files
    return paths.convert_file_list_to_relative_paths(all_files, game_root) if game_root else []

# Split a ROM game's DLC, update, extra and dependency files by json key, each relative to its folder
def _classify_rebased_files(game_supercategory, rebased_files):
    subfiles = {subfile_key: [] for subfile_key in _ROM_SUBFILE_KEYS}
    if game_supercategory not in [config.Supercategory.ROMS]:
        return subfiles
    for rebased_file in rebased_files:
        for subfile_key in _ROM_SUBFILE_KEYS:
            if rebased_file.startswith(subfile_key):
                subfiles[subfile_key].append(paths.get_filename_front_slice(rebased_file))
                break
    return subfiles

# Fill the file, DLC, update, extra, dependency and transform keys from the game root; returns the best game file
def _fill_game_file_keys(
    json_obj,
    game_supercategory,
    game_root,
    locker_type = None,
    verbose = False,
    exit_on_failure = False):

    # Get rebased files
    rebased_files = list_game_root_files(
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    subfiles = _classify_rebased_files(game_supercategory, rebased_files)

    # Get best game file
    best_game_file = None
    if game_supercategory in [config.Supercategory.ROMS]:
        best_game_file = gamecollection.find_best_game_file(paths.convert_to_top_level_paths(rebased_files))
        best_game_file = paths.get_filename_file(best_game_file)

    # Set common keys
    if isinstance(rebased_files, list) and len(rebased_files) > 0:
        json_obj.fill_value(config.JSON_KEY_FILES, rebased_files)
    for subfile_key in _ROM_SUBFILE_KEYS:
        if len(subfiles[subfile_key]) > 0:
            json_obj.fill_value(subfile_key, subfiles[subfile_key])
    if isinstance(best_game_file, str) and len(best_game_file) > 0:
        json_obj.fill_value(config.JSON_KEY_TRANSFORM_FILE, best_game_file)
    return best_game_file

# Give a computer game an empty store section, seeded with a generated id and names for manually imported platforms
def _fill_computer_store_keys(json_obj, store_obj, game_name):
    if not store_obj:
        return
    json_obj.fill_value(store_obj.get_key(), {})
    if json_obj.get_platform() in config.manual_import_platforms:
        game_regular_name = gamenaming.derive_regular_name_from_game_name(game_name)
        json_obj.fill_subvalue(store_obj.get_key(), config.JSON_KEY_STORE_APPID, strings.generate_unique_id())
        json_obj.fill_subvalue(store_obj.get_key(), config.JSON_KEY_STORE_APPNAME, strings.get_slug_string(game_regular_name))
        json_obj.fill_subvalue(store_obj.get_key(), config.JSON_KEY_STORE_NAME, game_regular_name)

# Fill one store subdata key from the latest store json, keeping a real build id over a default one and pruning child paths
def _merge_store_subdata_key(json_obj, store_key, latest_jsondata, store_subdata_key):
    if not latest_jsondata.has_key(store_subdata_key):
        return
    if store_subdata_key == config.JSON_KEY_STORE_BUILDID:
        existing_buildid = json_obj.get_subvalue(store_key, config.JSON_KEY_STORE_BUILDID)
        new_buildid = latest_jsondata.get_value(store_subdata_key)
        if existing_buildid and existing_buildid != config.DEFAULT_BUILDID and new_buildid == config.DEFAULT_BUILDID:
            return
    json_obj.fill_subvalue(store_key, store_subdata_key, latest_jsondata.get_value(store_subdata_key))
    if store_subdata_key == config.JSON_KEY_STORE_PATHS:
        store_paths = json_obj.get_subvalue(store_key, store_subdata_key, [])
        store_paths = paths.prune_child_paths(store_paths)
        json_obj.set_subvalue(store_key, store_subdata_key, store_paths)

# Merge the store's latest json for the game into its store section
def _merge_latest_store_jsondata(
    json_obj,
    store_obj,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get latest jsondata
    if not store_obj:
        return
    latest_jsondata = store_obj.get_latest_jsondata(
        identifier = json_obj.get_subvalue(store_obj.get_key(), store_obj.get_info_identifier_key()),
        branch = json_obj.get_subvalue(store_obj.get_key(), config.JSON_KEY_STORE_BRANCHID),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Merge current data
    if not latest_jsondata:
        return
    for store_subdata_key in config.json_keys_store_subdata:
        _merge_store_subdata_key(json_obj, store_obj.get_key(), latest_jsondata, store_subdata_key)

# Fill a ROM game's store or launch keys and merge the store's latest json; other supercategories are left alone
def _fill_rom_keys(
    json_obj,
    game_supercategory,
    game_category,
    game_name,
    best_game_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    if game_supercategory not in [config.Supercategory.ROMS]:
        return
    store_obj = stores.get_store_by_platform(
        store_platform = json_obj.get_platform(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Set computer keys, or other platforms' launch file
    if game_category == config.Category.COMPUTER:
        _fill_computer_store_keys(json_obj, store_obj, game_name)
    elif isinstance(best_game_file, str) and len(best_game_file) > 0:
        json_obj.fill_value(config.JSON_KEY_LAUNCH_FILE, best_game_file)

    # Merge latest store data
    _merge_latest_store_jsondata(
        json_obj = json_obj,
        store_obj = store_obj,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Write the json data and clean the file, sorting keys and dropping empty values
def write_and_clean_json_file(
    json_file_path,
    json_obj,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Write json file
    success = serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean json file
    success = serialization.clean_json_file(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Fill the json's file, ROM and store keys from the game root and the store, then write it sorted
def _refill_and_write_game_json(
    json_obj,
    json_file_path,
    game_supercategory,
    game_category,
    game_name,
    game_root,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Fill file keys
    best_game_file = _fill_game_file_keys(
        json_obj = json_obj,
        game_supercategory = game_supercategory,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Fill rom keys
    _fill_rom_keys(
        json_obj = json_obj,
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_name = game_name,
        best_game_file = best_game_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Write json file
    return write_and_clean_json_file(
        json_file_path = json_file_path,
        json_obj = json_obj,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Refill the game's JSON with its file, DLC, update, extra and launch entries from the game root, merge the store's latest data, and write it sorted
def update_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory):
        return True

    # Read json data
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    json_obj = read_game_json_obj(
        json_file_path = json_file_path,
        game_subcategory = game_subcategory,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not json_obj:
        return False

    # Refill and write json file
    return _refill_and_write_game_json(
        json_obj = json_obj,
        json_file_path = json_file_path,
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_name = game_name,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Create then update the game's json file from the game root
def _create_and_update_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create json file
    success = create_game_json_file(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update json file
    success = update_game_json_file(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Write the disc playlist when asked, so the json picks it as the game file, then create and update the json
def _build_game_json_in_root(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root,
    locker_type = None,
    create_disc_playlists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create disc playlist, so the json picks it as the game file
    if create_disc_playlists and game_supercategory == config.Supercategory.ROMS:
        success = playlist.generate_disc_playlist(
            source_dir = game_root,
            playlist_name = game_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Create and update json file
    return _create_and_update_game_json_file(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create and refresh the game's JSON from its locker folder, first writing a disc playlist when asked; False when the folder is missing
def build_game_json_file(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_root = None,
    locker_type = None,
    create_disc_playlists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    game_root = gamecollection.resolve_game_root(game_supercategory, game_category, game_subcategory, game_name, game_root, locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Log categories
    logger.log_info("Building json [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
        (game_category, game_subcategory, game_name))

    # Build json file in the game root
    return _build_game_json_in_root(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        game_root = game_root,
        locker_type = locker_type,
        create_disc_playlists = create_disc_playlists,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build the JSON of every locker game in one category's chosen subcategories; stops at the first failure
def _build_category_json_files(
    game_supercategory,
    game_category,
    selected_subcategories = None,
    locker_type = None,
    create_disc_playlists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    category_subcategories = config.subcategory_map[game_category]
    if selected_subcategories:
        category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
    for game_subcategory in category_subcategories:
        game_names = gamecollection.find_locker_game_names(
            game_supercategory,
            game_category,
            game_subcategory,
            locker_type)
        for game_name in game_names:
            success = build_game_json_file(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                locker_type = locker_type,
                create_disc_playlists = create_disc_playlists,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Build the JSON of every locker ROM game in the chosen categories and subcategories; stops at the first failure
def build_all_game_json_files(
    locker_type = None,
    categories = None,
    subcategories = None,
    create_disc_playlists = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            success = _build_category_json_files(
                game_supercategory = game_supercategory,
                game_category = game_category,
                selected_subcategories = selected_subcategories,
                locker_type = locker_type,
                create_disc_playlists = create_disc_playlists,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Should be successful
    return True

############################################################

# The identifier-to-name map of the category's JSON ignore file, created empty when missing; {} when the supercategory takes none
def get_game_json_ignore_entries(
    game_supercategory,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory):
        return {}

    # Get json file path
    json_file_path = environment.get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory)

    # Create file if necessary
    if not paths.does_path_exist(json_file_path):
        fileops.touch_file(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = serialization.read_json_file(
        src = json_file_path,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return json_file_data

# Write the ignore entries sorted, then clean the file of empty values
def _write_game_json_ignore_entries(
    json_file_path,
    json_obj,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Write json file
    serialization.write_json_file(
        src = json_file_path,
        json_data = json_obj.get_data(),
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean json file
    success = serialization.clean_json_file(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Record an identifier and game name in the category's JSON ignore file, creating it when missing
def add_game_json_ignore_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_identifier,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_json_file_possible(game_supercategory):
        return True

    # Read json data
    json_file_data = get_game_json_ignore_entries(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create json data object and add entry
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = gamenaming.derive_game_platform_from_categories(game_subcategory))
    json_obj.set_value(game_identifier, game_name)

    # Write json file
    return _write_game_json_ignore_entries(
        json_file_path = environment.get_game_json_metadata_ignore_file(game_supercategory, game_category, game_subcategory),
        json_obj = json_obj,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# The directory to build a game's JSON from: the input path when given, else the game's folder
# under the locker base's Gaming folder when given, else None for its locker folder
def _get_json_game_root(game_supercategory, game_category, game_subcategory, game_name, input_path, locker_base_dir):
    if input_path:
        return input_path
    if locker_base_dir:
        game_offset = environment.get_locker_gaming_files_offset(
            game_supercategory,
            game_category,
            game_subcategory,
            game_name)
        return paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING, game_offset)
    return None

# (supercategory, category, subcategory, name, game_root, json_file) for each game stored in the
# locker, or under the locker base, for the given categories; only game_name when it is given
def get_json_build_games(categories, game_name = None, input_path = None, locker_type = None, locker_base_dir = None):
    games = []
    for game_supercategory, game_category, game_subcategory in categories:
        game_names = gamecollection.find_locker_game_names(
            game_supercategory,
            game_category,
            game_subcategory,
            locker_type,
            locker_base_dir)
        if game_name:
            game_names = [g for g in game_names if g == game_name]
        for name in game_names:
            game_root = _get_json_game_root(game_supercategory, game_category, game_subcategory, name, input_path, locker_base_dir)
            json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, name)
            games.append((game_supercategory, game_category, game_subcategory, name, game_root, json_file))
    return games

# Build the JSON file of each game from get_json_build_games; quits at the first failure
def build_json_files_for_games(games, locker_type = None, create_disc_playlists = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for game_supercategory, game_category, game_subcategory, game_name, game_root, _ in games:
        success = build_game_json_file(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            game_root = game_root,
            locker_type = locker_type,
            create_disc_playlists = create_disc_playlists,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Build of json file failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                quit_program = True)

# The JSON files of every game in every category: (those listing no files, those not marked playable)
def find_problem_game_json_files(verbose = False, exit_on_failure = False):
    json_files_no_files = []
    json_files_unplayable = []
    for game_supercategory, game_category, game_subcategory, game_name in gamecollection.iterate_all_json_game_names():
        game_info = gameinfo.GameInfo(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        game_files = game_info.get_files()
        if isinstance(game_files, list) and len(game_files) == 0:
            json_files_no_files.append(game_info.get_json_file())
        if not game_info.is_playable():
            json_files_unplayable.append(game_info.get_json_file())
    return json_files_no_files, json_files_unplayable

# Log the heading and then each file, when there are any files
def _log_json_file_list(heading, json_files):
    if not json_files:
        return
    logger.log_info(heading)
    for json_file in json_files:
        logger.log_info(json_file)

# Log the games whose JSON file lists no files, those not marked playable, or both, as the
# analyze mode picks; changes nothing
def analyze_game_json_files(mode = config.AnalyzeModeType.ALL, verbose = False, exit_on_failure = False):
    json_files_no_files, json_files_unplayable = find_problem_game_json_files(verbose, exit_on_failure)
    if mode in (config.AnalyzeModeType.ALL, config.AnalyzeModeType.MISSING_GAME_FILES):
        _log_json_file_list("Games with no files:", json_files_no_files)
    if mode in (config.AnalyzeModeType.ALL, config.AnalyzeModeType.UNPLAYABLE_GAMES):
        _log_json_file_list("Games marked as unplayable:", json_files_unplayable)

# The JSON metadata files that exist for the games in every category
def find_existing_game_json_files():
    json_files = []
    for game_supercategory, game_category, game_subcategory, game_name in gamecollection.iterate_all_json_game_names():
        json_file = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
        if paths.is_path_file(json_file):
            json_files.append(json_file)
    return json_files

# Sort the keys of each JSON file and remove its empty values
def clean_game_json_files(json_files, verbose = False, pretend_run = False, exit_on_failure = False):
    for json_file in json_files:
        serialization.clean_json_file(
            src = json_file,
            sort_keys = True,
            remove_empty_values = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
