# Local imports
import joybox.config as config
import joybox.logger as logger
import joybox.paths as paths
import joybox.fileops as fileops
import joybox.archive as archive
import joybox.locker as locker
import joybox.gameinfo as gameinfo
import joybox.stores as stores
import joybox.storebase as storebase
import joybox.hashing as hashing
import joybox.strings as strings
from joybox import runtime

############################################################

# Check if save dir is packable
def is_save_dir_packable(input_save_dir, output_save_dir = None):
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

# Can save be packed
def can_save_be_packed(game_info):
    input_save_dir = game_info.get_save_dir()
    return is_save_dir_packable(input_save_dir)

# Can save be unpacked
def can_save_be_unpacked(game_info):
    input_save_dir = game_info.get_local_save_dir()
    output_save_dir = game_info.get_save_dir()
    return is_save_dir_unpackable(input_save_dir, output_save_dir)

############################################################

# Pack save
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
    if not is_save_dir_packable(input_save_dir, output_save_dir):
        if verbose:
            logger.log_info(f"No save data found for {game_info.get_name()}")
        return False

    # Pack save directory
    return _pack_save_dir(
        game_info = game_info,
        input_save_dir = input_save_dir,
        output_save_dir = output_save_dir,
        locker_type = locker_type,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Pack a save directory already known to hold save data
def _pack_save_dir(
    game_info,
    input_save_dir,
    output_save_dir,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Log packing
    logger.log_info(f"Packing save for {game_info.get_name()}")

    # Make output save dir
    success = fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False
    try:
        return _archive_and_backup_save(
            game_info = game_info,
            input_save_dir = input_save_dir,
            output_save_dir = output_save_dir,
            tmp_dir = tmp_dir_result,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

# Archive save into a temporary directory and back it up
def _archive_and_backup_save(
    game_info,
    input_save_dir,
    output_save_dir,
    tmp_dir,
    locker_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get save archive info
    tmp_save_archive_file = paths.join_paths(tmp_dir, game_info.get_name() + config.ArchiveFileType.ZIP.cval())
    out_save_archive_file = paths.join_paths(output_save_dir, game_info.get_name() + "_" + str(runtime.get_current_timestamp()) + config.ArchiveFileType.ZIP.cval())

    # Get excludes
    input_excludes = []
    if game_info.get_category() == config.Category.COMPUTER:
        input_excludes = [config.SaveType.WINE.val(), config.SaveType.SANDBOXIE.val()]

    # Archive save
    success = archive.create_archive_from_folder(
        archive_file = tmp_save_archive_file,
        source_dir = input_save_dir,
        excludes = input_excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Unable to archive save",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Test archive
    success = archive.test_archive(
        archive_file = tmp_save_archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Unable to validate save",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Check if already archived
    found_files = hashing.find_duplicate_archives(
        filename = tmp_save_archive_file,
        directory = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if found_files:
        logger.log_info("Save is already packed, skipping")
        return True

    # The local archive directory is what duplicate checks and unpacking read
    locker_types = [config.LockerType.LOCAL]
    if locker_type not in (None, config.LockerType.LOCAL):
        locker_types.append(locker_type)

    # Backup archive
    logger.log_info(f"Backing up save to {output_save_dir}")
    dest_rel_path = locker.convert_to_relative_path(out_save_archive_file)
    for backup_locker_type in locker_types:
        success = locker.backup(
            src = tmp_save_archive_file,
            dest_rel_path = dest_rel_path,
            locker_type = backup_locker_type,
            show_progress = True,
            skip_existing = True,
            skip_identical = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error(
                message = "Unable to backup save",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory())
            return False

    # Log success
    logger.log_info("Save packed successfully")
    return True

# Pack all saves
def pack_all_saves(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
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

    # Should be successful
    return True

############################################################

# Unpack save
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

    # Log unpacking
    logger.log_info(f"Unpacking save for {game_info.get_name()}")

    # Get latest save archive, whose timestamped name sorts last
    latest_save_archive = strings.sort_strings(paths.build_file_list(input_save_dir))[-1]

    # Make output save dir
    success = fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Unpack save archive
    if verbose:
        logger.log_info(f"Extracting from {latest_save_archive}")
    success = archive.extract_archive(
        archive_file = latest_save_archive,
        extract_dir = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(
            message = "Unable to unpack save",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Check result
    if not pretend_run and paths.is_directory_empty(output_save_dir):
        logger.log_error(
            message = "Unpacked save is empty",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Log success
    logger.log_info("Save unpacked successfully")
    return True

# Unpack all saves
def unpack_all_saves(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
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
                    if not can_save_be_unpacked(game_info):
                        continue
                    success = unpack_save(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Get store path entries
def get_store_path_entries(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.get_store_by_platform(game_info.get_platform())
    if not store_obj:
        return []

    # Get paths
    store_paths = store_obj.add_path_variants(game_info.get_store_paths())

    # Get translation map
    translation_map = store_obj.build_path_translation_map(
        appid = game_info.get_store_appid(),
        appname = game_info.get_store_name())

    # Translate paths
    translated_paths = []
    for path in store_paths:
        relative_path = storebase.convert_from_tokenized_path(path, store_type = store_obj.get_type())
        for base_key, key_replacements in translation_map.items():
            if base_key not in path:
                continue
            for key_replacement in key_replacements:
                entry = {}
                entry["full"] = path.replace(base_key, key_replacement)
                entry["relative"] = relative_path
                if entry not in translated_paths:
                    translated_paths.append(entry)
    return translated_paths

# Import store game save paths
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

# Import store game save
def import_store_game_save(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return True

# Export store game save
def export_store_game_save(
    game_info,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False
    try:

        # Get store path entries
        store_path_entries = get_store_path_entries(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Copy store files
        at_least_one_copy = False
        for store_path_entry in store_path_entries:
            path_full = store_path_entry.get("full")
            path_relative = store_path_entry.get("relative")
            if verbose:
                logger.log_info(f"Checking path: {path_full}")
            if not paths.does_directory_contain_files(path_full):
                continue
            success = fileops.smart_copy(
                src = path_full,
                dest = paths.join_paths(tmp_dir_result, path_relative),
                show_progress = True,
                skip_existing = True,
                ignore_symlinks = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
            at_least_one_copy = True
        if not at_least_one_copy:
            return True

        # Pack copied files, which a pretend run never wrote
        return _pack_save_dir(
            game_info = game_info,
            input_save_dir = tmp_dir_result,
            output_save_dir = game_info.get_local_save_dir(),
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)

############################################################

# Import local game save paths
def import_local_game_save_paths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return True

# Import local game save
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

# Export local game save
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

# Import game save paths
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
    else:
        return import_local_game_save_paths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Import all game save paths
def import_all_game_save_paths(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
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
                    success = import_game_save_paths(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

# Import game save
def import_game_save(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.is_store_platform(game_info.get_platform()):
        return import_store_game_save(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return import_local_game_save(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Import all game save
def import_all_game_saves(
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
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
                    success = import_game_save(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

# Export game save
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
    else:
        return export_local_game_save(
            game_info = game_info,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Export all game save
def export_all_game_save(
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for game_supercategory in [config.Supercategory.ROMS]:
        for game_category in config.Category.members():
            for game_subcategory in config.subcategory_map[game_category]:
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
                    success = export_game_save(
                        game_info = game_info,
                        locker_type = locker_type,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################
