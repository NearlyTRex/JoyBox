# Local imports
from joybox import fileops
from joybox import gamecollection
from joybox import stores
from .purchase import download_game_store_purchase
from .uploading import upload_game_files

############################################################

# Determine if store game files should be backed up
def should_backup_store_game_files(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
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

# Download the store's latest build into a temp dir and upload it to the locker; True without work when the stored build is current
def backup_store_game_files(
    game_info,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if game files should be backed up
    should_backup = should_backup_store_game_files(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not should_backup:
        return True

    # Download the files into a temporary directory and upload them from there
    with fileops.temporary_directory(verbose = verbose) as tmp_dir_result:
        if not tmp_dir_result:
            return False
        success = download_game_store_purchase(
            game_info = game_info,
            output_dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        return bool(upload_game_files(
            game_info = game_info,
            game_root = tmp_dir_result,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure))

###########################################################

# Determine if game files should be backed up
def should_backup_game_files(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return should_backup_store_game_files(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    # A local game's copy is the master, with no upstream to fetch it again from
    return False

# Back up a store game's latest build; local games are the master copy, so they pass with nothing done
def backup_game_files(
    game_info,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return backup_store_game_files(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    # A local game's copy is the master, with no upstream to fetch it again from
    return True

# Back up every ROM game in the collection; stops at the first failure
def backup_all_game_files(
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        success = backup_game_files(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

###########################################################
