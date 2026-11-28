# Local imports
from joybox import config
from joybox import logger
from joybox import environment
from joybox import fileops
from joybox import gamecollection
from joybox import gamenaming
from joybox import metadata
from joybox import metadataentry
from joybox import paths
from joybox import metadatacollector
from joybox import stores
from joybox import strings
from .jsondata import read_game_json_data
from .selection import iterate_selected_json_games

############################################################

# Determine if game metadata files are possible
def are_game_metadata_file_possible(
    game_supercategory):
    return game_supercategory == config.Supercategory.ROMS

############################################################

# The category's metadata file, loaded when it exists, else an empty Metadata
def load_metadata_file(metadata_file_path, verbose = False, exit_on_failure = False):
    metadata_obj = metadata.Metadata()
    if paths.does_path_exist(metadata_file_path):
        metadata_obj.import_from_metadata_file(
            metadata_file = metadata_file_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    return metadata_obj

# Write the whole metadata file from the Metadata, replacing what was there
def write_metadata_file(
    metadata_obj,
    metadata_file_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file_path,
        append_existing = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# A new entry for the game pointing at its json file, defaulting players, coop and playable and keeping an http url
def build_new_game_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_url = None,
    initial_data = None):

    # Get json file path
    json_file_path = environment.get_game_json_metadata_file(game_supercategory, game_category, game_subcategory, game_name)
    json_file_path = paths.rebase_file_path(
        path = json_file_path,
        old_base_path = environment.get_game_json_metadata_root_dir(),
        new_base_path = "")

    # Create game entry
    game_entry = metadataentry.MetadataEntry()
    if isinstance(initial_data, metadataentry.MetadataEntry):
        game_entry.merge(initial_data)
    game_entry.set_supercategory(game_supercategory)
    game_entry.set_category(game_category)
    game_entry.set_subcategory(game_subcategory)
    game_entry.set_game(game_name)
    game_entry.set_platform(gamenaming.derive_game_platform_from_categories(game_subcategory))
    game_entry.set_file(json_file_path)
    if not game_entry.get_players():
        game_entry.set_players("1")
    if not game_entry.get_coop():
        game_entry.set_coop("No")
    if not game_entry.get_playable():
        game_entry.set_playable("Yes")
    if isinstance(game_url, str) and len(game_url) > 0 and game_url.startswith("http"):
        game_entry.set_url(game_url)
    return game_entry

# Add the game to its category's metadata file with default players, coop and playable values; True without writing when it is already listed
def create_game_metadata_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    game_url = None,
    initial_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check categories
    if not are_game_metadata_file_possible(game_supercategory):
        return True

    # Get platform
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)

    # Load metadata file
    metadata_file_path = environment.get_game_metadata_file(game_category, game_subcategory)
    metadata_obj = load_metadata_file(metadata_file_path, verbose = verbose, exit_on_failure = exit_on_failure)
    if metadata_obj.has_game(game_platform, game_name):
        return True

    # Set game entry
    game_entry = build_new_game_entry(game_supercategory, game_category, game_subcategory, game_name, game_url, initial_data)
    metadata_obj.set_game(game_platform, game_name, game_entry)

    # Write metadata file
    write_metadata_file(
        metadata_obj = metadata_obj,
        metadata_file_path = metadata_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# The metadata file path, Metadata, json data and entry of a listed game that needs updating; None when it does not
def _find_game_entry_to_update(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = None,
    force = False,
    verbose = False,
    exit_on_failure = False):

    # Check keys
    if not isinstance(keys, list) or len(keys) == 0:
        keys = config.metadata_keys_downloadable

    # Check categories
    if not are_game_metadata_file_possible(game_supercategory):
        return None

    # Load metadata file
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    metadata_file_path = environment.get_game_metadata_file(game_category, game_subcategory)
    metadata_obj = load_metadata_file(metadata_file_path, verbose = verbose, exit_on_failure = exit_on_failure)
    if not metadata_obj.has_game(game_platform, game_name):
        return None

    # Get json data
    json_obj = read_game_json_data(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Determine if update is needed
    game_entry = metadata_obj.get_game(game_platform, game_name)
    if not force and not game_entry.is_missing_data(keys):
        return None
    return metadata_file_path, metadata_obj, json_obj, game_entry

# Latest metadata from the game's store by its json identifier, or from the metadata collectors when it has none
def fetch_latest_game_metadata(
    json_obj,
    game_platform,
    game_name,
    stats = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.get_store_by_platform(
        store_platform = game_platform,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest metadata
    if store_obj:
        return store_obj.get_latest_metadata(
            identifier = json_obj.get_subvalue(store_obj.get_key(), store_obj.get_metadata_identifier_key()) if json_obj else None,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return metadatacollector.collect_metadata_from_all(
        game_platform = game_platform,
        game_name = game_name,
        keys_to_check = config.metadata_keys_downloadable,
        stats = stats,
        verbose = verbose,
        pretend_run = pretend_run)

# Fill the listed game's missing keys, or all keys when forced, from its store or the metadata collectors and rewrite the metadata file
def update_game_metadata_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = None,
    force = False,
    stats = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find game entry to update
    found = _find_game_entry_to_update(game_supercategory, game_category, game_subcategory, game_name, keys, force, verbose, exit_on_failure)
    if not found:
        return True
    metadata_file_path, metadata_obj, json_obj, game_entry = found
    _refresh_game_metadata_entry(
        metadata_file_path, metadata_obj, json_obj, game_entry, game_subcategory, game_name,
        stats = stats,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Merge the latest store or collector metadata into the game entry and rewrite its metadata file
def _refresh_game_metadata_entry(
    metadata_file_path,
    metadata_obj,
    json_obj,
    game_entry,
    game_subcategory,
    game_name,
    stats = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Merge latest data
    game_platform = gamenaming.derive_game_platform_from_categories(game_subcategory)
    latest_metadata = fetch_latest_game_metadata(json_obj, game_platform, game_name, stats, verbose, pretend_run, exit_on_failure)
    if latest_metadata:
        game_entry.merge(latest_metadata)
        game_entry.sync_assets()

    # Update game entry
    metadata_obj.set_game(game_platform, game_name, game_entry)

    # Write metadata file
    write_metadata_file(
        metadata_obj = metadata_obj,
        metadata_file_path = metadata_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Ensure the game has a metadata entry, then fill its missing keys from the store or the collectors
def build_game_metadata_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = None,
    force = False,
    stats = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log categories
    logger.log_info("Building metadata [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
        (game_category, game_subcategory, game_name))

    # Create metadata entry
    success = create_game_metadata_entry(
        game_supercategory, game_category, game_subcategory, game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update metadata entry
    return update_game_metadata_entry(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        keys = keys,
        force = force,
        stats = stats,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build the metadata entry of every JSON ROM game in the chosen categories, logging collector stats; stops at the first failure
def build_all_game_metadata_entries(
    keys = None,
    categories = None,
    subcategories = None,
    locker_type = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    stats = metadatacollector.CollectionStats()
    success = True
    for game_supercategory, game_category, game_subcategory, game_name in iterate_selected_json_games(
        categories, subcategories, locker_type):
        success = build_game_metadata_entry(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            keys = keys,
            force = force,
            stats = stats,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            break
    stats.log_summary()
    return success

############################################################

# One HTML table row for a metadata entry, using the odd or even row template by its counter
def _render_metadata_entry_row(game_entry, game_entry_id, game_platform, metadata_counter):

    # Get entry info
    game_entry_name = game_entry.get_game()
    game_entry_natural_name = gamenaming.derive_regular_name_from_game_name(game_entry_name)
    game_entry_players = game_entry.get_players()
    game_entry_coop = game_entry.get_coop()
    game_entry_urlname = strings.encode_url_string(game_entry_natural_name, use_plus = True)
    game_entry_info = (
        game_entry_id,
        game_platform,
        game_entry_name,
        game_entry_players,
        game_entry_coop,
        game_entry_urlname,
        game_entry_urlname
    )

    # Add entry (using odd/even templates)
    if (metadata_counter % 2) == 0:
        return config.PUBLISH_HTML_ENTRY_EVEN % game_entry_info
    return config.PUBLISH_HTML_ENTRY_ODD % game_entry_info

# HTML rows for every entry of the subcategory's metadata file, numbered per platform; returns the rows and the next counter
def _render_subcategory_rows(metadata_file, metadata_counter):

    # Read metadata
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(metadata_file)

    # Iterate through each platform/entry
    rows = ""
    for game_platform in metadata_obj.get_sorted_platforms():
        game_entry_id = 1
        for game_entry in metadata_obj.get_sorted_entries(game_platform):
            rows += _render_metadata_entry_row(game_entry, game_entry_id, game_platform, metadata_counter)
            metadata_counter += 1
            game_entry_id += 1
    return rows, metadata_counter

# HTML rows for every metadata entry across the category's subcategories, alternating odd and even templates
def _render_category_rows(game_supercategory, game_category):

    # Set metadata counter so we can use alternating row templates
    metadata_counter = 1

    # Iterate through each subcategory for the given category
    category_rows = ""
    for game_subcategory in config.subcategory_map[game_category]:

        # Check categories
        if not are_game_metadata_file_possible(game_supercategory):
            continue

        # Get metadata file
        metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
        if not paths.is_path_file(metadata_file):
            continue

        # Add subcategory rows
        rows, metadata_counter = _render_subcategory_rows(metadata_file, metadata_counter)
        category_rows += rows
    return category_rows

# Render the category's metadata entries as an HTML table into the published metadata dir, one row per game
def publish_game_metadata_entries(
    game_supercategory,
    game_category,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Add header, rows and footer
    publish_contents = config.PUBLISH_HTML_HEADER % game_category
    publish_contents += _render_category_rows(game_supercategory, game_category)
    publish_contents += config.PUBLISH_HTML_FOOTER

    # Write publish file
    success = fileops.touch_file(
        src = paths.join_paths(environment.get_game_published_metadata_root_dir(), game_category + ".html"),
        contents = publish_contents,
        encoding = None,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Write the HTML page of each chosen ROM category, skipping categories holding none of the chosen subcategories
def publish_all_game_metadata_entries(
    categories = None,
    subcategories = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:

            # Pages cover a whole category; skip categories holding none of the selected subcategories
            if selected_subcategories and not any(sc in selected_subcategories for sc in config.subcategory_map[game_category]):
                continue

            # Publish metadata
            success = publish_game_metadata_entries(
                game_supercategory = game_supercategory,
                game_category = game_category,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

############################################################

# (supercategory, category, subcategory, name, metadata_file) for each game with JSON metadata
# in the given categories, only the one named game_name when it is given
def get_metadata_games(categories, game_name = None):
    games = []
    for game_supercategory, game_category, game_subcategory in categories:
        game_names = gamecollection.find_json_game_names(
            game_supercategory,
            game_category,
            game_subcategory)
        if game_name:
            game_names = [g for g in game_names if g == game_name]
        for name in game_names:
            metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
            games.append((game_supercategory, game_category, game_subcategory, name, metadata_file))
    return games

# Build the metadata entry of each game from get_metadata_games, logging the collection
# summary at the end, or before quitting at the first failure
def build_metadata_entries_for_games(games, verbose = False, pretend_run = False, exit_on_failure = False):
    stats = metadatacollector.CollectionStats()
    for game_supercategory, game_category, game_subcategory, game_name, _ in games:
        success = build_game_metadata_entry(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            stats = stats,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            stats.log_summary()
            logger.log_error(
                message = "Build of metadata file failed!",
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                quit_program = True)
    stats.log_summary()
