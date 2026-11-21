# Local imports
import joybox.logger as logger
import joybox.paths as paths
import joybox.environment as environment
import joybox.cryption as cryption
import joybox.locker as locker
import joybox.lockerinfo as lockerinfo
from joybox import gamecollection
from .hashing import build_hash_files

############################################################

# Upload game files
def upload_game_files(
    game_info,
    game_root = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    if not paths.is_path_directory(game_root):
        game_root = environment.get_locker_gaming_files_dir(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            game_name = game_info.get_name(),
            locker_type = locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Get passphrase
    passphrase = lockerinfo.LockerInfo(locker_type).get_passphrase()
    if not cryption.is_passphrase_valid(passphrase):
        logger.log_error("No passphrase configured for locker %s" % locker_type)
        return False

    # Encrypt all files
    success = cryption.encrypt_files(
        src = game_root,
        passphrase = passphrase,
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Hash all files
    success = build_hash_files(
        game_info = game_info,
        game_root = game_root,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload all files
    success = locker.sync_to_remote(
        src = game_root,
        verbose = verbose,
        locker_type = locker_type,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Upload all game files
def upload_all_game_files(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, pretend_run, exit_on_failure):
        success = upload_game_files(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################
