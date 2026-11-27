# Local imports
from joybox import config
from joybox import logger
from joybox import environment
from joybox import fileops
from joybox import gameinfo
from joybox import gamecollection
from joybox import asset
from joybox import network
from joybox import paths
from joybox import locker
from joybox import stores
from joybox import metadataassetcollector

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

# Log an asset step failure against the game's categories
def _log_asset_error(game_info, message):
    logger.log_error(
        message = message,
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory())

# Locker file the game's asset of this type is backed up to
def _get_output_asset_file(game_info, asset_type):
    return environment.get_locker_gaming_asset_file(
        game_info.get_category(),
        game_info.get_subcategory(),
        game_info.get_name(),
        asset_type)

# Reachable asset url from the game's store, or from the metadata collectors when it has none; None after logging
def _find_reachable_asset_url(
    game_info,
    asset_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        _log_asset_error(game_info, "No reachable url for asset %s " % (asset_type))
        return None
    return latest_asset_url

# Download the asset url into the temp dir and convert it to the locker's format; the converted file, or None after logging
def _download_and_convert_asset(
    game_info,
    asset_type,
    asset_url,
    tmp_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get temp asset
    output_asset_ext = paths.get_filename_extension(_get_output_asset_file(game_info, asset_type))
    tmp_asset_file_original = paths.join_paths(tmp_dir, paths.replace_invalid_path_characters(paths.get_filename_file(asset_url)))
    tmp_asset_file_converted = tmp_asset_file_original + output_asset_ext

    # Download asset
    success = asset.download_asset(
        asset_url = asset_url,
        asset_file = tmp_asset_file_original,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        _log_asset_error(game_info, "Download failed for asset %s " % (asset_type))
        return None

    # Convert asset
    success = asset.convert_asset(
        asset_src = tmp_asset_file_original,
        asset_dest = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        _log_asset_error(game_info, "Convert failed for asset %s " % (asset_type))
        return None
    return tmp_asset_file_converted

# Find the asset url, make its locker dir and fetch it converted into the temp dir; None after logging a failure
def _fetch_asset(
    game_info,
    asset_type,
    tmp_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get latest asset url
    latest_asset_url = _find_reachable_asset_url(
        game_info = game_info,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not latest_asset_url:
        return None

    # Make output asset dir
    fileops.make_directory(
        src = environment.get_locker_gaming_asset_dir(
            game_info.get_category(),
            game_info.get_subcategory(),
            asset_type),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download and convert asset
    return _download_and_convert_asset(
        game_info = game_info,
        asset_type = asset_type,
        asset_url = latest_asset_url,
        tmp_dir = tmp_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Clean the converted asset and back it up to its locker path; False after logging the failed step
def _clean_and_backup_asset(
    game_info,
    asset_type,
    asset_file,
    locker_type = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Clean asset
    success = asset.clean_asset(
        asset_file = asset_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        _log_asset_error(game_info, "Clean failed for asset %s " % (asset_type))
        return False

    # Backup asset
    dest_rel_path = locker.convert_to_relative_path(_get_output_asset_file(game_info, asset_type))
    success = locker.backup(
        src = asset_file,
        dest_rel_path = dest_rel_path,
        locker_type = locker_type,
        show_progress = True,
        skip_existing = skip_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        _log_asset_error(game_info, "Backup failed for asset %s " % (asset_type))
        return False
    return True

# Fetch one asset type from the game's store or the metadata collectors, convert and clean it, then back it up to the locker; False on any failed step
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

    # Download into a temporary directory, removed whatever the outcome
    with fileops.temporary_directory(verbose = verbose) as tmp_dir_result:
        if not tmp_dir_result:
            return False
        tmp_asset_file = _fetch_asset(
            game_info = game_info,
            asset_type = asset_type,
            tmp_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not tmp_asset_file:
            return False
        return _clean_and_backup_asset(
            game_info = game_info,
            asset_type = asset_type,
            asset_file = tmp_asset_file,
            locker_type = locker_type,
            skip_existing = skip_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Download every minimum asset type for one game; stops at the first failure
def _download_game_assets(
    game_info,
    locker_type = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for asset_type in config.AssetMinType.members():
        success = download_metadata_asset(
            game_info = game_info,
            asset_type = asset_type,
            skip_existing = skip_existing,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Download assets for every json game in a category's chosen subcategories; stops at the first failure
def _download_category_assets(
    game_supercategory,
    game_category,
    selected_subcategories = None,
    locker_type = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    category_subcategories = config.subcategory_map[game_category]
    if selected_subcategories:
        category_subcategories = [sc for sc in category_subcategories if sc in selected_subcategories]
    for game_subcategory in category_subcategories:
        game_names = gamecollection.find_json_game_names(
            game_supercategory,
            game_category,
            game_subcategory,
            locker_type)
        for game_name in game_names:
            game_info = gameinfo.GameInfo(
                game_supercategory = game_supercategory,
                game_category = game_category,
                game_subcategory = game_subcategory,
                game_name = game_name,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            success = _download_game_assets(
                game_info = game_info,
                locker_type = locker_type,
                skip_existing = skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

# Download every minimum asset type for each ROM game in the chosen categories and subcategories; stops at the first failure
def download_all_metadata_assets(
    categories = None,
    subcategories = None,
    locker_type = None,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    selected_categories = config.Category.from_list(categories) if categories else config.Category.members()
    selected_subcategories = config.Subcategory.from_list(subcategories) if subcategories else None
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in selected_categories:
            success = _download_category_assets(
                game_supercategory = game_supercategory,
                game_category = game_category,
                selected_subcategories = selected_subcategories,
                locker_type = locker_type,
                skip_existing = skip_existing,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Should be successful
    return True

############################################################

# Download one asset type for each of the games, quitting with an error at the first failure
def download_metadata_asset_for_games(
    game_infos,
    asset_type,
    skip_existing = False,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in game_infos:
        success = download_metadata_asset(
            game_info = game_info,
            asset_type = asset_type,
            skip_existing = skip_existing,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Download of metadata assets failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)
