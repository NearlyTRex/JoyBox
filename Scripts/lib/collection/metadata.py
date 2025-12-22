# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import environment
import fileops
import gameinfo
import platforms
import metadata
import metadataentry
import paths
import metadatacollector
import stores
import strings
from .jsondata import read_game_json_data

############################################################

# Determine if game metadata files are possible
def are_game_metadata_file_possible(
    game_supercategory,
    game_category = None,
    game_subcategory = None):
    return (game_supercategory == config.Supercategory.ROMS)

############################################################

# Create game metadata entry
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
    if not are_game_metadata_file_possible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Get metadata file path
    metadata_file_path = environment.get_game_metadata_file(game_category, game_subcategory)

    # Load metadata file
    metadata_obj = metadata.Metadata()
    if paths.does_path_exist(metadata_file_path):
        metadata_obj.import_from_metadata_file(
            metadata_file = metadata_file_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if metadata_obj.has_game(game_platform, game_name):
        return True

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
    game_entry.set_platform(game_platform)
    game_entry.set_file(json_file_path)
    if not game_entry.get_players():
        game_entry.set_players("1")
    if not game_entry.get_coop():
        game_entry.set_coop("No")
    if not game_entry.get_playable():
        game_entry.set_playable("Yes")
    if isinstance(game_url, str) and len(game_url) > 0 and game_url.startswith("http"):
        game_entry.set_url(game_url)

    # Set game entry
    metadata_obj.set_game(game_platform, game_name, game_entry)

    # Write metadata file
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file_path,
        append_existing = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Update game metadata entry
def update_game_metadata_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = [],
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check keys
    if not isinstance(keys, list) or len(keys) == 0:
        keys = config.metadata_keys_downloadable

    # Check categories
    if not are_game_metadata_file_possible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)

    # Get metadata file path
    metadata_file_path = environment.get_game_metadata_file(game_category, game_subcategory)

    # Load metadata file
    metadata_obj = metadata.Metadata()
    if paths.does_path_exist(metadata_file_path):
        metadata_obj.import_from_metadata_file(
            metadata_file = metadata_file_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not metadata_obj.has_game(game_platform, game_name):
        return True

    # Get json data
    json_obj = read_game_json_data(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get game entry
    game_entry = metadata_obj.get_game(game_platform, game_name)

    # Determine if update is needed
    should_update = False
    if force:
        should_update = True
    else:
        should_update = game_entry.is_missing_data(keys)
    if not should_update:
        return True

    # Get store
    store_obj = stores.GetStoreByPlatform(
        store_platform = game_platform,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest metadata
    latest_metadata = None
    if store_obj:
        latest_metadata = store_obj.get_latest_metadata(
            identifier = json_obj.get_subvalue(store_obj.get_key(), store_obj.get_metadata_identifier_key()),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        latest_metadata = metadatacollector.CollectMetadataFromAll(
            game_platform = game_platform,
            game_name = game_name,
            keys_to_check = config.metadata_keys_downloadable,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Merge latest data
    if latest_metadata:
        game_entry.merge(latest_metadata)
        game_entry.sync_assets()

    # Update game entry
    metadata_obj.set_game(game_platform, game_name, game_entry)

    # Write metadata file
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file_path,
        append_existing = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

############################################################

# Build game metadata entry
def build_game_metadata_entry(
    game_supercategory,
    game_category,
    game_subcategory,
    game_name,
    keys = [],
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log categories
    logger.log_info("Building metadata [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
        (game_category, game_subcategory, game_name))

    # Create metadata entry
    success = create_game_metadata_entry(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Update metadata entry
    success = update_game_metadata_entry(
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        keys = keys,
        force = force,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Build all game metadata entries
def build_all_game_metadata_entries(
    keys = [],
    categories = None,
    subcategories = None,
    force = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            category_subcategories = config.subcategory_map[game_category]
            if selected_subcategories:
                category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
            for game_subcategory in category_subcategories:
                game_platform = gameinfo.derive_game_platform_from_categories(game_category, game_subcategory)
                game_names = gameinfo.find_json_game_names(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:
                    success = build_game_metadata_entry(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        keys = keys,
                        force = force,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Publish game metadata entries
def publish_game_metadata_entries(
    game_supercategory,
    game_category,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Set metadata counter so we can use alternating row templates
    metadata_counter = 1

    # Add header
    publish_contents = config.publish_html_header % game_category

    # Iterate through each subcategory for the given category
    for game_subcategory in config.subcategory_map[game_category]:

        # Check categories
        if not are_game_metadata_file_possible(game_supercategory, game_category, game_subcategory):
            continue

        # Get metadata file
        metadata_file = environment.get_game_metadata_file(game_category, game_subcategory)
        if not paths.is_path_file(metadata_file):
            continue

        # Read metadata
        metadata_obj = metadata.Metadata()
        metadata_obj.import_from_metadata_file(metadata_file)

        # Iterate through each platform/entry
        for game_platform in metadata_obj.get_sorted_platforms():
            game_entry_id = 1
            for game_entry in metadata_obj.get_sorted_entries(game_platform):

                    # Get entry info
                    game_entry_name = game_entry.get_game()
                    game_entry_natural_name = gameinfo.derive_regular_name_from_game_name(game_entry_name)
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
                        publish_contents += config.publish_html_entry_even % game_entry_info
                    else:
                        publish_contents += config.publish_html_entry_odd % game_entry_info
                    metadata_counter += 1
                    game_entry_id += 1

    # Add footer
    publish_contents += config.publish_html_footer

    # Write publish file
    success = fileops.touch_file(
        src = paths.join_paths(environment.get_game_published_metadata_root_dir(), game_category + ".html"),
        contents = publish_contents,
        encoding = None,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Publish all game metadata entries
def publish_all_game_metadata_entries(
    categories = None,
    subcategories = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:

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
