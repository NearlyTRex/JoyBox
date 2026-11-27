# Local imports
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import cryption
from joybox import locker
from joybox import lockerinfo
from joybox import gamecollection
from .hashing import build_hash_files

############################################################

# The given game root when it is a directory, else the game's locker files dir
def _resolve_game_root(game_info, game_root = None, locker_type = None):
    if paths.is_path_directory(game_root):
        return game_root
    return environment.get_locker_gaming_files_dir(
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory(),
        game_name = game_info.get_name(),
        locker_type = locker_type)

# Encrypt the game root's files in place, replacing the originals, then rebuild their hashes
def _encrypt_and_hash_files(
    game_info,
    game_root,
    passphrase,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
    return success

# Encrypt the game's files in place, rebuild their hashes and sync them to the remote locker; False without a valid locker passphrase
def upload_game_files(
    game_info,
    game_root = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    game_root = _resolve_game_root(game_info, game_root, locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Get passphrase
    passphrase = lockerinfo.LockerInfo(locker_type).get_passphrase()
    if not cryption.is_passphrase_valid(passphrase):
        logger.log_error("No passphrase configured for locker %s" % locker_type)
        return False

    # Encrypt and hash all files
    success = _encrypt_and_hash_files(
        game_info = game_info,
        game_root = game_root,
        passphrase = passphrase,
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

# Upload every ROM game in the collection; stops at the first failure
def upload_all_game_files(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
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

# Each selected game paired with the directory its files upload from: input_path when
# given, else the game's folder in the source locker
def get_upload_game_roots(
    parser,
    generation_mode = None,
    source_locker = None,
    input_path = None,
    verbose = False,
    exit_on_failure = False):
    games_to_process = []
    for game_info in gamecollection.iterate_selected_game_infos(
        parser = parser,
        generation_mode = generation_mode,
        locker_type = source_locker,
        verbose = verbose,
        exit_on_failure = exit_on_failure):
        game_root = input_path or environment.get_locker_gaming_files_dir(
            game_info.get_supercategory(),
            game_info.get_category(),
            game_info.get_subcategory(),
            game_info.get_name(),
            source_locker)
        games_to_process.append((game_info, game_root))
    return games_to_process

# Encrypt and upload each game's files from its root to the destination locker; quits on the first game that fails
def upload_game_roots(
    games_to_process,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info, game_root in games_to_process:
        success = upload_game_files(
            game_info = game_info,
            game_root = game_root,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Upload of game files failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)
