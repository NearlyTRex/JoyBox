# Imports
import os
import sys

# Local imports
import config
import system
import environment
import fileops
import gameinfo
import stores
from .purchase import DownloadGameStorePurchase
from .uploading import UploadGameFiles

############################################################

# Determine if store game files should be backed up
def ShouldBackupStoreGameFiles(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return False

    # Check if downloadable
    if not store_obj.can_download_purchases():
        return False

    # Get store info
    store_info_identifier = game_info.get_store_info_identifier()
    store_branchid = game_info.get_store_branchid()
    store_buildid = game_info.get_store_buildid()

    # Get latest version
    latest_version = store_obj.get_latest_version(
        identifier = store_info_identifier,
        branch = store_branchid,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check versions
    return latest_version != store_buildid

# Backup store game files
def BackupStoreGameFiles(
    game_info,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if game files should be backed up
    should_backup = ShouldBackupStoreGameFiles(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not should_backup:
        return True

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Download files
    success = DownloadGameStorePurchase(
        game_info = game_info,
        output_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload files
    success = UploadGameFiles(
        game_info = game_info,
        game_root = tmp_dir_result,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True

###########################################################

# Determine if local game files should be backed up
def ShouldBackupLocalGameFiles(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return False

# Backup local game files
def BackupLocalGameFiles(
    game_info,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return True

###########################################################

# Determine if game files should be backed up
def ShouldBackupGameFiles(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return ShouldBackupStoreGameFiles(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return ShouldBackupLocalGameFiles(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Backup game files
def BackupGameFiles(
    game_info,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return BackupStoreGameFiles(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return BackupLocalGameFiles(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Backup all game files
def BackupAllGameFiles(
    locker_type,
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
                    success = BackupGameFiles(
                        game_info = game_info,
                        locker_type = locker_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

###########################################################
