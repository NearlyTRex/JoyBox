# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import gameinfo
import asset
import network
import locker
import stores
import metadataassetcollector

############################################################

# Check if metadata asset exists
def DoesMetadataAssetExist(game_info, asset_type):

    # Check if exists
    output_asset_file = environment.GetLockerGamingAssetFile(
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory(),
        game_name = game_info.get_name(),
        asset_type = asset_type)
    return system.DoesPathExist(output_asset_file)

############################################################

# Download metadata asset
def DownloadMetadataAsset(
    game_info,
    asset_type,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if asset exists
    asset_exists = DoesMetadataAssetExist(
        game_info = game_info,
        asset_type = asset_type)
    if skip_existing and asset_exists:
        return True

    # Get output asset
    output_asset_dir = environment.GetLockerGamingAssetDir(
        game_info.get_category(),
        game_info.get_subcategory(),
        asset_type)
    output_asset_file = environment.GetLockerGamingAssetFile(
        game_info.get_category(),
        game_info.get_subcategory(),
        game_info.get_name(),
        asset_type)
    output_asset_ext = system.GetFilenameExtension(output_asset_file)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get store
    store_obj = stores.GetStoreByPlatform(
        store_platform = game_info.get_platform(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get latest asset url
    latest_asset_url = None
    if store_obj:
        latest_asset_url = store_obj.GetLatestAssetUrl(
            identifier = game_info.get_store_asset_identifier(),
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        latest_asset_url = metadataassetcollector.FindMetadataAsset(
            game_platform = game_info.get_platform(),
            game_name = game_info.get_name(),
            asset_type = asset_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if not network.IsUrlReachable(latest_asset_url):
        return False

    # Get temp asset
    tmp_asset_file_original = system.JoinPaths(tmp_dir_result, system.ReplaceInvalidPathCharacters(system.GetFilenameFile(latest_asset_url)))
    tmp_asset_file_converted = tmp_asset_file_original + output_asset_ext
    system.MakeDirectory(
        src = output_asset_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Download asset
    success = asset.DownloadAsset(
        asset_url = latest_asset_url,
        asset_file = tmp_asset_file_original,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError(
            message = "Download failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
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
        system.LogError(
            message = "Convert failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Clean asset
    success = asset.CleanAsset(
        asset_file = tmp_asset_file_converted,
        asset_type = asset_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError(
            message = "Clean failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Backup asset
    success = locker.BackupFiles(
        src = tmp_asset_file_converted,
        dest = output_asset_file,
        show_progress = True,
        skip_existing = skip_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError(
            message = "Backup failed for asset %s " % (asset_type),
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

# Download all metadata assets
def DownloadAllMetadataAssets(
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
                game_names = gameinfo.FindJsonGameNames(
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
                        success = DownloadMetadataAsset(
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
