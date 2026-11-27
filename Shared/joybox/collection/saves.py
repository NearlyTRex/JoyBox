# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import filebulk
from joybox import archive
from joybox import locker
from joybox import gamecollection
from joybox import stores
from joybox import storebase
from joybox import hashutil
from joybox import strings
from joybox import runtime

############################################################

# Check if save dir is packable
def is_save_dir_packable(input_save_dir):
    return paths.does_directory_contain_files(input_save_dir)

# Check if save dir is unpackable
def is_save_dir_unpackable(input_save_dir, output_save_dir):
    if not paths.is_path_directory(input_save_dir) or not paths.does_directory_contain_files(input_save_dir):
        return False
    if not paths.is_path_valid(output_save_dir):
        return False
    if paths.does_path_exist(output_save_dir):
        if not paths.is_path_directory(output_save_dir) or not paths.is_directory_empty(output_save_dir):
            return False
    return True

# Whether the game's save dir holds any files to archive
def can_save_be_packed(game_info):
    input_save_dir = game_info.get_save_dir()
    return is_save_dir_packable(input_save_dir)

# Whether the game has packed save archives and its save dir is missing or empty to receive them
def can_save_be_unpacked(game_info):
    input_save_dir = game_info.get_local_save_dir()
    output_save_dir = game_info.get_save_dir()
    return is_save_dir_unpackable(input_save_dir, output_save_dir)

############################################################

# Zip the game's save dir, or the given dir, into a timestamped archive backed up to the local locker and the chosen one; False when it holds no saves
def pack_save(
    game_info,
    save_dir = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get save dirs
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = game_info.get_save_dir()
    output_save_dir = game_info.get_local_save_dir()
    if not is_save_dir_packable(input_save_dir):
        if verbose:
            logger.log_info(f"No save data found for {game_info.get_name()}")
        return False

    # Pack save directory
    return pack_save_dir(
        game_info = game_info,
        input_save_dir = input_save_dir,
        output_save_dir = output_save_dir,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Log a save failure against the game's category
def log_save_error(game_info, message):
    logger.log_error(
        message = message,
        game_supercategory = game_info.get_supercategory(),
        game_category = game_info.get_category(),
        game_subcategory = game_info.get_subcategory())

# Pack a save directory already known to hold save data
def pack_save_dir(
    game_info,
    input_save_dir,
    output_save_dir,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make output save dir
    logger.log_info(f"Packing save for {game_info.get_name()}")
    success = fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Archive and back up through a temporary directory
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        return archive_and_backup_save(
            game_info = game_info,
            input_save_dir = input_save_dir,
            output_save_dir = output_save_dir,
            tmp_dir = tmp_dir,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Archive a save directory and test the archive, leaving out a computer game's wine and sandboxie prefixes
def create_save_archive(game_info, archive_file, input_save_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    input_excludes = []
    if game_info.get_category() == config.Category.COMPUTER:
        input_excludes = [config.SaveType.WINE.val(), config.SaveType.SANDBOXIE.val()]
    success = archive.create_archive_from_folder(
        archive_file = archive_file,
        source_dir = input_save_dir,
        excludes = input_excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        log_save_error(game_info, "Unable to archive save")
        return False
    success = archive.test_archive(
        archive_file = archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        log_save_error(game_info, "Unable to validate save")
        return False
    return True

# Get the lockers a save backs up to: always the local one, which duplicate checks and unpacking read
def get_save_locker_types(locker_type):
    if locker_type in (None, config.LockerType.LOCAL):
        return [config.LockerType.LOCAL]
    return [config.LockerType.LOCAL, locker_type]

# Back up a save archive to each locker given
def backup_save_archive(game_info, archive_file, dest_rel_path, locker_types, verbose = False, pretend_run = False, exit_on_failure = False):
    for locker_type in locker_types:
        success = locker.backup(
            src = archive_file,
            dest_rel_path = dest_rel_path,
            locker_type = locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            log_save_error(game_info, "Unable to backup save")
            return False
    return True

# Archive save into a temporary directory and back it up
def archive_and_backup_save(
    game_info,
    input_save_dir,
    output_save_dir,
    tmp_dir,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Archive save, unless an identical archive is already packed
    tmp_save_archive_file = paths.join_paths(tmp_dir, game_info.get_name() + config.ArchiveFileType.ZIP.cval())
    if not create_save_archive(game_info, tmp_save_archive_file, input_save_dir, verbose, pretend_run, exit_on_failure):
        return False
    found_files = hashutil.find_duplicate_archives(
        filename = tmp_save_archive_file,
        directory = output_save_dir)
    if found_files:
        logger.log_info("Save is already packed, skipping")
        return True

    # Backup archive under a timestamped name
    logger.log_info(f"Backing up save to {output_save_dir}")
    out_save_archive_file = paths.join_paths(
        output_save_dir, game_info.get_name() + "_" + str(runtime.get_current_timestamp()) + config.ArchiveFileType.ZIP.cval())
    if not backup_save_archive(
        game_info, tmp_save_archive_file, locker.convert_to_relative_path(out_save_archive_file),
        get_save_locker_types(locker_type), verbose, pretend_run, exit_on_failure):
        return False
    logger.log_info("Save packed successfully")
    return True

# Pack the save of every ROM game that has save files; stops at the first failure
def pack_all_saves(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        if not can_save_be_packed(game_info):
            continue
        success = pack_save(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Extract the newest packed save archive into the game's empty save dir; False when there is nothing to unpack
def unpack_save(
    game_info,
    save_dir = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get save dirs
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = game_info.get_local_save_dir()
    output_save_dir = game_info.get_save_dir()
    if not is_save_dir_unpackable(input_save_dir, output_save_dir):
        if verbose:
            logger.log_info(f"No packed save found for {game_info.get_name()}")
        return False

    # Unpack the latest save archive, whose timestamped name sorts last
    logger.log_info(f"Unpacking save for {game_info.get_name()}")
    latest_save_archive = strings.sort_strings(paths.build_file_list(input_save_dir))[-1]
    if not extract_save_archive(game_info, latest_save_archive, output_save_dir, verbose, pretend_run, exit_on_failure):
        return False
    logger.log_info("Save unpacked successfully")
    return True

# Extract a save archive into a save directory, checking it held something
def extract_save_archive(game_info, archive_file, output_save_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    success = fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if verbose:
        logger.log_info(f"Extracting from {archive_file}")
    success = archive.extract_archive(
        archive_file = archive_file,
        extract_dir = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        log_save_error(game_info, "Unable to unpack save")
        return False
    if not pretend_run and paths.is_directory_empty(output_save_dir):
        log_save_error(game_info, "Unpacked save is empty")
        return False
    return True

# Unpack the newest save of every ROM game that can receive one; stops at the first failure
def unpack_all_saves(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        if not can_save_be_unpacked(game_info):
            continue
        success = unpack_save(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# Get a store path's entries, one per replacement of each translation key it holds
def translate_store_path(path, relative_path, translation_map):
    entries = []
    for base_key, key_replacements in translation_map.items():
        if base_key in path:
            entries += [{"full": path.replace(base_key, key_replacement), "relative": relative_path} for key_replacement in key_replacements]
    return entries

# The game's store save paths with tokens expanded, each as a full path and its relative path; [] for non-store games
def get_store_path_entries(
    game_info):

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return []

    # Translate each path variant, without repeats
    translation_map = store_obj.build_path_translation_map(
        appid = game_info.get_store_appid(),
        appname = game_info.get_store_name())
    translated_paths = []
    for path in store_obj.add_path_variants(game_info.get_store_paths()):
        relative_path = storebase.convert_from_tokenized_path(path, store_type = store_obj.get_type())
        for entry in translate_store_path(path, relative_path, translation_map):
            if entry not in translated_paths:
                translated_paths.append(entry)
    return translated_paths

# Add the paths inside the game's packed save archives, tokenized, to its store save paths and write its JSON file
def import_store_game_save_paths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get current paths
    save_paths = list(game_info.get_store_paths() or [])

    # Read save archives and add paths
    for archive_file in paths.build_file_list(game_info.get_local_save_dir()):
        archive_paths = archive.list_archive(
            archive_file = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        new_paths = []
        for archive_path in archive_paths:
            new_path = storebase.convert_to_tokenized_path(
                path = archive_path,
                store_type = game_info.get_main_store_type())
            new_paths.append(new_path)
        save_paths += new_paths

    # Update current paths
    save_paths = paths.prune_child_paths(set(save_paths))
    game_info.set_store_paths(save_paths)

    # Write back changes
    success = game_info.update_json_file(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success


# Copy the store save paths holding files into a directory, under their relative paths.
# Returns whether every copy succeeded, and whether there was anything to copy.
def copy_store_save_files(store_path_entries, dest_dir, verbose = False, pretend_run = False, exit_on_failure = False):
    copied = False
    for store_path_entry in store_path_entries:
        path_full = store_path_entry.get("full")
        if verbose:
            logger.log_info(f"Checking path: {path_full}")
        if not paths.does_directory_contain_files(path_full):
            continue
        success = filebulk.smart_copy(
            src = path_full,
            dest = paths.join_paths(dest_dir, store_path_entry.get("relative")),
            show_progress = True,
            skip_existing = True,
            ignore_symlinks = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False, copied
        copied = True
    return True, copied

# Copy the files under the game's store save paths into a temp dir and pack them as a save; True when none hold files
def export_store_game_save(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False

        # Copy store files
        store_path_entries = get_store_path_entries(
            game_info = game_info)
        success, copied = copy_store_save_files(store_path_entries, tmp_dir, verbose, pretend_run, exit_on_failure)
        if not success or not copied:
            return success

        # Pack copied files, which a pretend run never wrote
        return pack_save_dir(
            game_info = game_info,
            input_save_dir = tmp_dir,
            output_save_dir = game_info.get_local_save_dir(),
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

############################################################

# Unpack the game's newest save when it can be; True when there is nothing to unpack
def import_local_game_save(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if save can be unpacked
    if not can_save_be_unpacked(game_info):
        return True

    # Unpack save
    success = unpack_save(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Pack the game's save dir when it holds files; True when there is nothing to pack
def export_local_game_save(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if save can be packed
    if not can_save_be_packed(game_info):
        return True

    # Pack save
    success = pack_save(
        game_info = game_info,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Record save paths from a store game's packed archives; other games pass, as only store games record them
def import_game_save_paths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return import_store_game_save_paths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    # Only store games record save paths
    return True

# Record save paths for every ROM game in the collection; stops at the first failure
def import_all_game_save_paths(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        success = import_game_save_paths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Unpack a local game's newest save; store games pass, as their store restores saves
def import_game_save(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        # The store restores its own saves
        return True
    return import_local_game_save(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Restore the save of every ROM game in the collection; stops at the first failure
def import_all_game_saves(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        success = import_game_save(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Pack the save from the store save paths for store games, otherwise from the local save dir
def export_game_save(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return export_store_game_save(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return export_local_game_save(
        game_info = game_info,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Pack the save of every ROM game in the collection; stops at the first failure
def export_all_game_save(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_info in gamecollection.iterate_rom_game_infos(verbose, exit_on_failure):
        success = export_game_save(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

############################################################

# The handler for each save action and the error it logs when a game fails
def _get_save_action_handlers():
    return {
        config.SaveActionType.PACK: (pack_save, "Packing of save failed!"),
        config.SaveActionType.UNPACK: (unpack_save, "Unpacking of save failed!"),
        config.SaveActionType.IMPORT: (import_game_save, "Import of save failed!"),
        config.SaveActionType.EXPORT: (export_game_save, "Export of save failed!"),
        config.SaveActionType.IMPORT_SAVE_PATHS: (import_game_save_paths, "Import of save paths failed!"),
    }

# The selected games a save action has something to do for: Pack and Unpack skip games
# with nothing to pack or unpack, logging each in verbose mode
def get_save_action_games(parser, action, verbose = False, exit_on_failure = False):
    readiness_checks = {
        config.SaveActionType.PACK: can_save_be_packed,
        config.SaveActionType.UNPACK: can_save_be_unpacked,
    }
    is_ready = readiness_checks.get(action)
    games_to_process = []
    for game_info in gamecollection.iterate_selected_game_infos(
        parser = parser,
        verbose = verbose,
        exit_on_failure = exit_on_failure):
        if is_ready and not is_ready(game_info):
            if verbose:
                logger.log_info("Nothing to %s for %s" % (str(action).lower(), game_info.get_name()))
            continue
        games_to_process.append(game_info)
    return games_to_process

# Run a save action on each game, Pack and Export going to locker_type; quits on the first game that fails
def run_save_action(
    games,
    action,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    handler, error_message = _get_save_action_handlers()[action]
    for game_info in games:
        handler_kwargs = {
            "game_info": game_info,
            "verbose": verbose,
            "pretend_run": pretend_run,
            "exit_on_failure": exit_on_failure
        }
        if action in (config.SaveActionType.PACK, config.SaveActionType.EXPORT):
            handler_kwargs["locker_type"] = locker_type
        success = handler(**handler_kwargs)
        if not success:
            logger.log_error(
                message = error_message,
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory(),
                game_name = game_info.get_name(),
                quit_program = True)
