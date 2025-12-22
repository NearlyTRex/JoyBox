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
import asset
import network
import paths
import locker
import stores
import metadataassetcollector

############################################################

# Check if metadata asset exists
def does_metadata_asset_exist(game_info, asset_type):

    # Check if exists
    output_asset_file = environment.get_locker_gaming_asset_file(
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory(),
        game_name = game_info.get_name(),
        asset_type = asset_type)
    return paths.does_path_exist(output_asset_file)

############################################################

# Download metadata asset
def download_metadata_asset(
    game_info,
    asset_type,
    skip_existing = False,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if asset exists
    asset_exists = does_metadata_asset_exist(
        game_info = game_info,
        asset_type = asset_type)
    if skip_existing and asset_exists:
        return True

    # Get output asset
    output_asset_dir = environment.get_locker_gaming_asset_dir(
        game_info.get_category(),
        game_info.get_subcategory(),
        asset_type)
    output_asset_file = environment.get_locker_gaming_asset_file(
        game_info.get_category(),
        game_info.get_subcategory(),
        game_info.get_name(),
        asset_type)
    output_asset_ext = paths.get_filename_extension(output_asset_file)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get store
    store_obj = stores.get_store_by_platform(
        store_platform = game_info.get_platform(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest asset url
    latest_asset_url = None
    if store_obj:
        latest_asset_url = store_obj.get_latest_asset_url(
            identifier = game_info.get_store_asset_identifier(),
            asset_type = asset_type,
            game_name = game_info.get_name(),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        latest_asset_url = metadataassetcollector.find_metadata_asset(
            game_platform = game_info.get_platform(),
            game_name = game_info.get_name(),
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not network.is_url_reachable(latest_asset_url):
        return False

    # Get temp asset
    tmp_asset_file_original = paths.join_paths(tmp_dir_result, paths.replace_invalid_path_characters(paths.get_filename_file(latest_asset_url)))
    tmp_asset_file_converted = tmp_asset_file_original + output_asset_ext
    fileops.make_directory(
        src = output_asset_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download asset
    success = asset.download_asset(
        asset_url = latest_asset_url,
        asset_file = tmp_asset_file_original,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Download failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Convert asset
    success = asset.convert_asset(
        asset_src = tmp_asset_file_original,
        asset_dest = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Convert failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Clean asset
    success = asset.clean_asset(
        asset_file = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Clean failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Backup asset
    success = locker.backup_files(
        src = tmp_asset_file_converted,
        dest = output_asset_file,
        locker_type = locker_type,
        show_progress = True,
        skip_existing = skip_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Backup failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

# Download all metadata assets
def download_all_metadata_assets(
    categories = None,
    subcategories = None,
    skip_existing = False,
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
                game_names = gameinfo.find_json_game_names(
                    game_supercategory,
                    game_category,
                    game_subcategory)
                for game_name in game_names:
                    game_info = gameinfo.GameInfo(
                        game_supercategory = game_supercategory,
                        game_category = game_category,
                        game_subcategory = game_subcategory,
                        game_name = game_name,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    for asset_type in config.AssetMinType.members():
                        success = download_metadata_asset(
                            game_info = game_info,
                            asset_type = asset_type,
                            skip_existing = skip_existing,
                            verbose = verbose,
                            pretend_run = pretend_run,
                            exit_on_failure = exit_on_failure)
                        if not success:
                            return False

    # Should be successful
    return True

############################################################
