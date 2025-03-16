# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import gameinfo
import platforms
import metadata
import metadataentry

############################################################

# Determine if game metadata files are possible
def AreGameMetadataFilePossible(
    game_supercategory,
    game_category = None,
    game_subcategory = None):
    return (game_supercategory == config.Supercategory.ROMS)

############################################################

# Create metadata entry
def CreateMetadataEntry(
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
    if not AreGameMetadataFilePossible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get metadata file path
    metadata_file_path = environment.GetMetadataFile(game_category, game_subcategory)

    # Load metadata file
    metadata_obj = metadata.Metadata()
    if system.DoesPathExist(metadata_file_path):
        metadata_obj.import_from_metadata_file(
            metadata_file = metadata_file_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if metadata_obj.has_game(game_platform, game_name):
        return True

    # Get json file path
    json_file_path = environment.GetJsonMetadataFile(config.Supercategory.ROMS, game_category, game_subcategory, game_name)
    json_file_path = system.RebaseFilePath(
        path = json_file_path,
        old_base_path = environment.GetJsonMetadataRootDir(),
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

# Update metadata entry
def UpdateMetadataEntry(
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
    if not AreGameMetadataFilePossible(game_supercategory, game_category, game_subcategory):
        return True

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get metadata file path
    metadata_file_path = environment.GetMetadataFile(game_category, game_subcategory)

    # Load metadata file
    metadata_obj = metadata.Metadata()
    if system.DoesPathExist(metadata_file_path):
        metadata_obj.import_from_metadata_file(
            metadata_file = metadata_file_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not metadata_obj.has_game(game_platform, game_name):
        return True

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
        login = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest metadata
    latest_metadata = None
    if store_obj:
        latest_metadata = store_obj.GetLatestMetadata(
            identifier = json_obj.get_subvalue(store_obj.GetKey(), store_obj.GetMetadataIdentifierKey()),
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

# Build metadata entries
def BuildMetadataEntries(
    keys = [],
    force = False,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
                game_names = gameinfo.FindLockerGameNames(
                    game_supercategory,
                    game_category,
                    game_subcategory,
                    source_type)
                for game_name in game_names:

                    # Get scan path
                    scan_game_path = environment.GetLockerGamingFilesDir(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        source_type = source_type)

                    # Build metadata
                    if system.IsPathDirectory(scan_game_path):
                        system.LogInfo("Building metadata [Category: '%s', Subcategory: '%s', Name: '%s'] ..." %
                            (game_category, game_subcategory, game_name))

                        # Gather directories to scan
                        game_directories = set()
                        if platforms.IsLetterPlatform(game_platform):
                            for obj in system.GetDirectoryContents(scan_game_path):
                                game_directories.add(system.GetFilenameDirectory(system.JoinPaths(scan_game_path, obj)))
                        else:
                            game_directories.add(system.GetFilenameDirectory(scan_game_path))

                        # Add metadata entries
                        for game_directory in sorted(game_directories):
                            if game_directory.endswith(")"):
                                success = CreateMetadataEntry(
                                    game_supercategory = game_supercategory,
                                    game_category = game_category,
                                    game_subcategory = game_subcategory,
                                    game_name = system.GetDirectoryName(game_directory),
                                    verbose = verbose,
                                    pretend_run = pretend_run,
                                    exit_on_failure = exit_on_failure)
                                if not success:
                                    return False
                                success = UpdateMetadataEntry(
                                    game_supercategory = game_supercategory,
                                    game_category = game_category,
                                    game_subcategory = game_subcategory,
                                    game_name = system.GetDirectoryName(game_directory),
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

# Publish metadata entries
def PublishMetadataEntries(
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
        if not AreGameMetadataFilePossible(game_supercategory, game_category, game_subcategory):
            continue

        # Get metadata file
        metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
        if not system.IsPathFile(metadata_file):
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
                    game_entry_natural_name = gameinfo.DeriveRegularNameFromGameName(game_entry_name)
                    game_entry_players = game_entry.get_players()
                    game_entry_coop = game_entry.get_coop()
                    game_entry_urlname = system.EncodeUrlString(game_entry_natural_name, use_plus = True)
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
    success = system.TouchFile(
        src = system.JoinPaths(environment.GetPublishedMetadataRootDir(), game_category + ".html"),
        contents = publish_contents,
        encoding = None,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Publish all metadata entries
def PublishAllMetadataEntries(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():

            # Publish metadata
            success = PublishMetadataEntries(
                game_supercategory = game_supercategory,
                game_category = game_category,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

############################################################
