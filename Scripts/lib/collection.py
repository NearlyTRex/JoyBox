# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import gameinfo
import platforms
import system
import cryption
import network
import asset
import locker
import jsondata
import metadata
import metadataentry
import metadatacollector

############################################################

# Create game json file
def CreateGameJsonFile(
    game_category,
    game_subcategory,
    game_name,
    game_root = None,
    initial_data = None,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get base path
    base_path = environment.GetLockerGamingRomDir(game_category, game_subcategory, game_name)
    if system.IsPathValid(game_root):
        base_path = os.path.realpath(game_root)

    # Get json file path
    json_file_path = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

    # Build json data
    json_file_data = {}
    if isinstance(initial_data, dict):
        json_file_data = initial_data

    # Already existing json file
    if os.path.exists(json_file_path):
        json_file_data = system.ReadJsonFile(
            src = json_file_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get all files
    all_files = system.BuildFileList(base_path)
    if isinstance(passphrase, str) and len(passphrase) > 0:
        all_files = cryption.GetRealFilePaths(
            source_files = all_files,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get rebased files
    rebased_files = system.ConvertFileListToRelativePaths(all_files, base_path)

    # Build path lists
    all_main = []
    all_dlc = []
    all_updates = []
    all_extras = []
    all_dependencies = []
    for rebased_file in rebased_files:
        rebased_subfile = system.GetFilenameFrontSlice(rebased_file)
        if rebased_file.startswith(config.json_key_dlc):
            all_dlc.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_update):
            all_updates.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_extra):
            all_extras.append(rebased_subfile)
        elif rebased_file.startswith(config.json_key_dependencies):
            all_dependencies.append(rebased_subfile)
        else:
            all_main.append(rebased_file)

    # Build exe lists
    exe_main = [f for f in all_main if f.endswith(".exe") or f.endswith(".msi")]
    exe_dlc = [f for f in all_dlc if f.endswith(".exe") or f.endswith(".msi")]
    exe_updates = [f for f in all_updates if f.endswith(".exe") or f.endswith(".msi")]

    # Get top level paths
    top_level_paths = system.ConvertToTopLevelPaths(rebased_files)

    # Get best game file
    best_game_file = gameinfo.FindBestGameFile(top_level_paths)
    best_game_file = system.GetFilenameFile(best_game_file)

    # Get computer roots
    computer_root_dlc = os.path.join(config.token_setup_main_root, config.json_key_dlc)
    computer_root_updates = os.path.join(config.token_setup_main_root, config.json_key_update)

    # Get computer installers
    computer_installers = []
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_main, config.token_setup_main_root)
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_updates, computer_root_updates)
    computer_installers += system.ConvertFileListToAbsolutePaths(exe_dlc, computer_root_dlc)

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Set common keys
    json_obj.fill_value(config.json_key_files, rebased_files)
    json_obj.fill_value(config.json_key_dlc, all_dlc)
    json_obj.fill_value(config.json_key_update, all_updates)
    json_obj.fill_value(config.json_key_extra, all_extras)
    json_obj.fill_value(config.json_key_dependencies, all_dependencies)
    json_obj.fill_value(config.json_key_transform_file, best_game_file)

    # Set computer keys
    if game_category == config.game_category_computer:
        json_obj.fill_value(config.json_key_installer_exe, computer_installers)
        if game_subcategory == config.game_subcategory_amazon_games:
            json_obj.fill_value(config.json_key_amazon, {
                config.json_key_store_appid: "",
                config.json_key_store_name: ""
            })
        elif game_subcategory == config.game_subcategory_epic_games:
            json_obj.fill_value(config.json_key_epic, {
                config.json_key_store_appname: ""
            })
        elif game_subcategory == config.game_subcategory_gog:
            json_obj.fill_value(config.json_key_gog, {
                config.json_key_store_appid: "",
                config.json_key_store_appname: ""
            })
        elif game_subcategory == config.game_subcategory_itchio:
            json_obj.fill_value(config.json_key_itchio, {
                config.json_key_store_appid: "",
                config.json_key_store_appurl: "",
                config.json_key_store_name: ""
            })
        elif game_subcategory == config.game_subcategory_legacy_games:
            json_obj.fill_value(config.json_key_legacy, {
                config.json_key_store_appid: "",
                config.json_key_store_name: ""
            })
        elif game_subcategory == config.game_subcategory_steam:
            json_obj.fill_value(config.json_key_steam, {
                config.json_key_store_appid: "",
                config.json_key_store_branchid: config.steam_branch_format_public
            })

    # Set other platform keys
    else:
        json_obj.fill_value(config.json_key_launch_name, "REPLACEME")
        json_obj.fill_value(config.json_key_launch_file, best_game_file)

    # Create json directory
    success = system.MakeDirectory(
        dir = system.GetFilenameDirectory(json_file_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Write json file
    success = system.WriteJsonFile(
        src = json_file_path,
        json_data = json_obj.get_data(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean json file
    success = system.CleanJsonFile(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Create game json files
def CreateGameJsonFiles(
    game_category,
    game_subcategory,
    game_root,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_name in gameinfo.FindAllGameNames(game_root, game_category, game_subcategory):
        success = CreateGameJsonFile(
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            passphrase = passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Get game json ignore entries
def GetGameJsonIgnoreEntries(
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get json file path
    json_file_path = environment.GetJsonRomMetadataIgnoreFile(game_category, game_subcategory)

    # Create file if necessary
    if not os.path.exists(json_file_path):
        system.TouchFile(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return json_file_data

# Add game json ignore entry
def AddGameJsonIgnoreEntry(
    game_category,
    game_subcategory,
    game_identifier,
    game_name,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get json file path
    json_file_path = environment.GetJsonRomMetadataIgnoreFile(game_category, game_subcategory)

    # Create file if necessary
    if not os.path.exists(json_file_path):
        system.TouchFile(
            src = json_file_path,
            contents = "{}",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Read json data
    json_file_data = system.ReadJsonFile(
        src = json_file_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create json data object
    json_obj = jsondata.JsonData(
        json_data = json_file_data,
        json_platform = game_platform)

    # Add entry
    json_obj.set_value(game_identifier, game_name)

    # Write json file
    system.WriteJsonFile(
        src = json_file_path,
        json_data = json_obj.get_data(),
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean json file
    success = system.CleanJsonFile(
        src = json_file_path,
        sort_keys = True,
        remove_empty_values = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Add metadata entry
def AddMetadataEntry(
    game_category,
    game_subcategory,
    game_name,
    initial_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find metadata file
    metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
    if not metadata_file:
        return False

    # Load metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(
        metadata_file = metadata_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Derive game data
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)
    game_json_file = environment.GetJsonRomMetadataFile(game_category, game_subcategory, game_name)

    # Adjust json file path
    game_json_file = system.RebaseFilePath(
        path = game_json_file,
        old_base_path = environment.GetJsonRomsMetadataRootDir(),
        new_base_path = "")

    # Create new entry
    new_entry = metadataentry.MetadataEntry()
    if isinstance(initial_data, metadataentry.MetadataEntry):
        new_entry = initial_data
    new_entry.set_game(game_name)
    new_entry.set_platform(game_platform)
    new_entry.set_file(game_json_file)
    new_entry.set_players("1")
    new_entry.set_coop("No")
    new_entry.set_playable("Yes")

    # Add new entry
    metadata_obj.add_game(new_entry)

    # Write metadata file
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file,
        append_existing = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Add metadata entries
def AddMetadataEntries(
    game_category,
    game_subcategory,
    game_root,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_name in gameinfo.FindAllGameNames(game_root, game_category, game_subcategory):
        success = AddMetadataEntry(
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Update metadata entry
def UpdateMetadataEntry(
    game_category,
    game_subcategory,
    game_name,
    new_data = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Find metadata file
    metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
    if not metadata_file:
        return False

    # Load metadata file
    metadata_obj = metadata.Metadata()
    metadata_obj.import_from_metadata_file(
        metadata_file = metadata_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Derive game data
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get current entry
    current_entry = metadata_obj.get_game(game_platform, game_name)
    if not current_entry:
        return False

    # Update current data
    if isinstance(new_data, metadataentry.MetadataEntry):
        current_entry.merge(new_data)

    # Sync assets
    current_entry.sync_assets()

    # Update entry
    metadata_obj.set_game(game_platform, game_name, current_entry)

    # Write metadata file
    metadata_obj.export_to_metadata_file(
        metadata_file = metadata_file,
        append_existing = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Update metadata entries
def UpdateMetadataEntries(
    game_category,
    game_subcategory,
    game_root,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_name in gameinfo.FindAllGameNames(game_root, game_category, game_subcategory):
        success = UpdateMetadataEntry(
            game_category = game_category,
            game_subcategory = game_subcategory,
            game_name = game_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Scan for metadata entries
def ScanForMetadataEntries(
    game_dir,
    game_category,
    game_subcategory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Gather directories to scan
    scan_directories = []
    if game_platform in config.letter_platforms:
        for obj in system.GetDirectoryContents(game_dir):
            scan_directories.append(os.path.join(game_dir, obj))
    else:
        scan_directories.append(game_dir)

    # Add metadata entries
    for game_directory in game_directories:
        if game_directory.endswith(")"):
            success = AddMetadataEntry(
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = system.GetDirectoryName(game_directory),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

############################################################

# Publish metadata entries
def PublishMetadataEntries(
    game_category,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Set metadata counter so we can use alternating row templates
    metadata_counter = 1

    # Add header
    publish_contents = config.publish_html_header % game_category

    # Iterate through each subcategory for the given category
    for game_subcategory in config.game_subcategories[game_category]:

        # Get metadata file
        metadata_file = environment.GetMetadataFile(game_category, game_subcategory)
        if not os.path.isfile(metadata_file):
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
        src = os.path.join(environment.GetPublishedMetadataRootDir(), game_category + ".html"),
        contents = publish_contents,
        encoding = None,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Check if metadata asset exists
def DoesMetadataAssetExist(
    game_category,
    game_subcategory,
    game_name,
    asset_type):

    # Check if exists
    output_asset_file = environment.GetLockerGamingAssetFile(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        asset_type = asset_type)
    return system.DoesPathExist(output_asset_file)

# Download metadata asset
def DownloadMetadataAsset(
    game_category,
    game_subcategory,
    game_name,
    asset_url,
    asset_type,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get platform
    game_platform = gameinfo.DeriveGamePlatformFromCategories(game_category, game_subcategory)

    # Get output asset
    output_asset_dir = environment.GetLockerGamingAssetDir(game_category, game_subcategory, asset_type)
    output_asset_file = environment.GetLockerGamingAssetFile(game_category, game_subcategory, game_name, asset_type)
    output_asset_ext = system.GetFilenameExtension(output_asset_file)
    if skip_existing and system.DoesPathExist(output_asset_file):
        return True

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Check asset url
    if not network.IsUrlReachable(asset_url):
        asset_url = metadatacollector.CollectMetadataAssetFromAll(
            game_platform = game_platform,
            game_name = game_name,
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not network.IsUrlReachable(asset_url):
        return False

    # Get temp asset
    tmp_asset_file_original = os.path.join(tmp_dir_result, system.GetFilenameFile(asset_url))
    tmp_asset_file_converted = tmp_asset_file_original + output_asset_ext
    system.MakeDirectory(
        dir = output_asset_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download asset
    success = asset.DownloadAsset(
        asset_url = asset_url,
        asset_file = tmp_asset_file_original,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Convert asset
    success = asset.ConvertAsset(
        asset_src = tmp_asset_file_original,
        asset_dest = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean asset
    success = asset.CleanAsset(
        asset_file = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Move asset
    success = system.MoveFileOrDirectory(
        src = tmp_asset_file_converted,
        dest = output_asset_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload asset
    success = locker.UploadPath(
        src = output_asset_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

############################################################
