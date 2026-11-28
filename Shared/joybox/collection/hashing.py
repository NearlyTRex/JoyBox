# Local imports
from joybox import config
from joybox import paths
from joybox import environment
from joybox import hashing
from joybox import lockerinfo
from joybox import gamecollection
from joybox import gamenaming
from joybox import logger
from joybox import prompts

###########################################################

# Hash the game's files, encrypted fields included, into its category's JSON hash file; defaults to its locker folder, False when none exists
def build_hash_files(
    game_info,
    game_root = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get game root
    game_root = gamecollection.resolve_game_root(
        game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory(), game_info.get_name(), game_root, locker_type)
    if not paths.is_path_directory(game_root):
        return False

    # Get hash info
    hash_file = environment.get_game_hashes_metadata_file(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())
    game_name_path = gamenaming.derive_game_name_path_from_name(game_info.get_name(), game_info.get_platform())
    hash_offset = paths.join_paths(game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory(), game_name_path)

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)

    # Hash files
    success = hashing.hash_files(
        src = game_root,
        output_file = hash_file,
        offset = hash_offset,
        passphrase = locker_info.get_passphrase(),
        hash_format = config.HashFormatType.JSON,
        include_enc_fields = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Drop entries from a category's hash file whose files are gone from the locker root; True when there is no hash file
def clean_missing_hash_entries(
    game_supercategory,
    game_category,
    game_subcategory,
    locker_root,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash file
    hash_file = environment.get_game_hashes_metadata_file(game_supercategory, game_category, game_subcategory)
    if not paths.is_path_file(hash_file):
        return True

    # Clean missing entries
    return hashing.clean_missing_hash_entries(
        hash_file = hash_file,
        locker_root = locker_root,
        hash_format = config.HashFormatType.JSON,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Hash the files of every ROM game in the collection; stops at the first failure
def build_all_hash_files(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return gamecollection.run_on_all_rom_games(
        build_hash_files,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

############################################################

# Sort the hash file of the game's category; False when that file is missing
def sort_hash_file(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash file
    hash_file = environment.get_game_hashes_metadata_file(
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory())
    if not paths.is_path_file(hash_file):
        return False

    # Sort hash file
    success = hashing.sort_hash_file(
        src = hash_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Yield each existing hash file across all supercategories, categories and subcategories
def iterate_existing_hash_files():
    for game_supercategory, game_category, game_subcategory in gamecollection.iterate_all_categories():
        hash_file = environment.get_game_hashes_metadata_file(
            game_supercategory = game_supercategory,
            game_category = game_category,
            game_subcategory = game_subcategory)
        if paths.is_path_file(hash_file):
            yield hash_file

# Sort every existing hash file across all supercategories, categories and subcategories
def sort_all_hash_files(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Sort hash files
    for hash_file in iterate_existing_hash_files():
        success = hashing.sort_hash_file(
            src = hash_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

############################################################

# The directory to hash a game from: the input path when given, else its folder under the
# locker base's Gaming folder when given, else its folder in the locker
def get_hash_game_root(game_info, input_path = None, locker_type = None, locker_base_dir = None):
    if input_path:
        return input_path
    if locker_base_dir:
        game_offset = environment.get_locker_gaming_files_offset(
            game_info.get_supercategory(),
            game_info.get_category(),
            game_info.get_subcategory(),
            game_info.get_name())
        return paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING, game_offset)
    return environment.get_locker_gaming_files_dir(
        game_info.get_supercategory(),
        game_info.get_category(),
        game_info.get_subcategory(),
        game_info.get_name(),
        locker_type)

# (game_info, game_root) for each game, with the directory get_hash_game_root picks for it
def get_hash_game_roots(game_infos, input_path = None, locker_type = None, locker_base_dir = None):
    return [(game_info, get_hash_game_root(game_info, input_path, locker_type, locker_base_dir)) for game_info in game_infos]

# Hash each (game_info, game_root) pair into its subcategory hash file; quits at the first failure
def build_hash_files_for_games(games, locker_type = None, verbose = False, pretend_run = False, exit_on_failure = False):
    for game_info, game_root in games:
        success = build_hash_files(
            game_info = game_info,
            game_root = game_root,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            gamecollection.log_game_error_and_quit(game_info, "Build of hash files failed!")

# Drop the missing-file entries from the hash file of each subcategory the games cover, once
# per subcategory, against the locker base's or the locker's Gaming root; quits on a failure
def clean_missing_hash_entries_for_games(game_infos, locker_type = None, locker_base_dir = None, verbose = False, pretend_run = False, exit_on_failure = False):
    locker_root = paths.join_paths(locker_base_dir, config.LockerFolderType.GAMING) if locker_base_dir else environment.get_locker_gaming_root_dir(locker_type)
    subcategories_cleaned = set()
    for game_info in game_infos:
        subcategory_key = (game_info.get_supercategory(), game_info.get_category(), game_info.get_subcategory())
        if subcategory_key in subcategories_cleaned:
            continue
        subcategories_cleaned.add(subcategory_key)
        success = clean_missing_hash_entries(
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory(),
            locker_root = locker_root,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Clean of missing hash entries failed!",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                quit_program = True)

# After a preview of the directories, hash each game from the one get_hash_game_root picks,
# then, when delete_missing, drop the entries of files gone from each subcategory's hash file;
# quits at the first failure
def build_selected_hash_files(
    game_infos,
    input_path = None,
    locker_type = None,
    locker_base_dir = None,
    delete_missing = False,
    show_preview = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Collect games to process
    games_to_process = get_hash_game_roots(game_infos, input_path, locker_type, locker_base_dir)

    # Show preview
    if show_preview:
        details = [game_root for _, game_root in games_to_process]
        if not prompts.prompt_for_preview("Build game hash files", details):
            logger.log_warning("Operation cancelled by user")
            return

    # Build hash files, then clean missing hash entries
    build_hash_files_for_games(games_to_process, locker_type, verbose, pretend_run, exit_on_failure)
    if delete_missing:
        selected_game_infos = [game_info for game_info, _ in games_to_process]
        clean_missing_hash_entries_for_games(selected_game_infos, locker_type, locker_base_dir, verbose, pretend_run, exit_on_failure)
