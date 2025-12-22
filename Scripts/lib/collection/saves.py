# Imports
import os
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import archive
import locker
import gameinfo
import stores
import storebase
import hashing

############################################################

# Check if save dir is packable
def IsSaveDirPackable(input_save_dir, output_save_dir):
    return paths.does_directory_contain_files(input_save_dir)

# Check if save dir is unpackable
def IsSaveDirUnpackable(input_save_dir, output_save_dir):
    if not paths.is_path_directory(input_save_dir) or paths.is_directory_empty(input_save_dir):
        return False
    if paths.is_path_directory(output_save_dir) or not paths.is_directory_empty(output_save_dir):
        return False
    return True

# Can save be packed
def CanSaveBePacked(game_info):
    input_save_dir = game_info.get_save_dir()
    return IsSaveDirPackable(input_save_dir)

# Can save be unpacked
def CanSaveBeUnpacked(game_info):
    input_save_dir = game_info.get_local_save_dir()
    output_save_dir = game_info.get_save_dir()
    return IsSaveDirUnpackable(input_save_dir, output_save_dir)

############################################################

# Pack save
def PackSave(
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
    if not IsSaveDirPackable(input_save_dir, output_save_dir):
        if verbose:
            logger.log_info(f"No save data found for {game_info.get_name()}")
        return False

    # Log packing
    logger.log_info(f"Packing save for {game_info.get_name()}")

    # Make output save dir
    fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get save archive info
    tmp_save_archive_file = paths.join_paths(tmp_dir_result, game_info.get_name() + config.ArchiveFileType.ZIP.cval())
    out_save_archive_file = paths.join_paths(output_save_dir, game_info.get_name() + "_" + str(environment.get_current_timestamp()) + config.ArchiveFileType.ZIP.cval())

    # Get excludes
    input_excludes = []
    if game_info.get_category() == config.Category.COMPUTER:
        input_excludes = [config.SaveType.WINE.val(), config.SaveType.SANDBOXIE.val()]

    # Archive save
    success = archive.CreateArchiveFromFolder(
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
    success = archive.TestArchive(
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
    found_files = hashing.FindDuplicateArchives(
        filename = tmp_save_archive_file,
        directory = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(found_files) > 0:
        logger.log_info("Save is already packed, skipping")
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return True

    # Backup archive
    logger.log_info(f"Backing up save to {output_save_dir}")
    success = locker.BackupFiles(
        src = tmp_save_archive_file,
        dest = out_save_archive_file,
        locker_type = locker_type,
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

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Log success
    logger.log_info("Save packed successfully")

    # Check result
    return paths.does_path_exist(out_save_archive_file)

# Pack all saves
def PackAllSaves(
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
                    success = PackSave(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################

# Unpack save
def UnpackSave(
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
    if not IsSaveDirUnpackable(input_save_dir, output_save_dir):
        if verbose:
            logger.log_info(f"No packed save found for {game_info.get_name()}")
        return False

    # Log unpacking
    logger.log_info(f"Unpacking save for {game_info.get_name()}")

    # Make output save dir
    fileops.make_directory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not paths.is_directory_empty(output_save_dir):
        logger.log_info("Save already unpacked, skipping")
        return True

    # Get latest save archive
    archived_save_files = paths.build_file_list(input_save_dir)
    latest_save_archive = archived_save_files[-1] if archived_save_files else None
    if not latest_save_archive:
        if verbose:
            logger.log_info("No archived saves found")
        return False

    # Unpack save archive
    if verbose:
        logger.log_info(f"Extracting from {latest_save_archive}")
    success = archive.ExtractArchive(
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

    # Log success
    logger.log_info("Save unpacked successfully")

    # Check result
    return not paths.is_directory_empty(output_save_dir)

# Unpack all saves
def UnpackAllSaves(
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
                    success = UnpackSave(
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
def GetStorePathEntries(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get store
    store_obj = stores.GetStoreByPlatform(game_info.get_platform())
    if not store_obj:
        return []

    # Get paths
    paths = game_info.get_store_paths()
    paths = store_obj.add_path_variants(paths)

    # Get translation map
    translation_map = store_obj.build_path_translation_map(
        appid = game_info.get_store_appid(),
        appname = game_info.get_store_name())

    # Translate paths
    translated_paths = []
    for path in paths:
        for base_key in translation_map.keys():
            for key_replacement in translation_map[base_key]:
                entry = {}
                entry["full"] = path.replace(base_key, key_replacement)
                entry["relative"] = storebase.convert_from_tokenized_path(path, store_type = store_obj.get_type())
                translated_paths.append(entry)
    return translated_paths

# Import store game save paths
def ImportStoreGameSavePaths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get current paths
    save_paths = game_info.get_store_paths()

    # Read save files and add paths
    for archive_file in paths.build_file_list(game_info.get_save_dir()):
        archive_paths = archive.ListArchive(
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
    save_paths = list(set(save_paths))
    save_paths = paths.prune_child_paths(save_paths)
    game_info.set_store_paths(save_paths)

    # Write back changes
    success = game_info.update_json_file(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Import store game save
def ImportStoreGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return True

# Export store game save
def ExportStoreGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get store path entries
    store_path_entries = GetStorePathEntries(
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
        if paths.does_directory_contain_files(path_full):
            success = fileops.smart_copy(
                src = path_full,
                dest = paths.join_paths(tmp_dir_result, path_relative),
                show_progress = True,
                skip_existing = True,
                ignore_symlinks = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                at_least_one_copy = True
    if not at_least_one_copy:
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return True

    # Pack save
    success = PackSave(
        game_info = game_info,
        save_dir = tmp_dir_result,
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

############################################################

# Import local game save paths
def ImportLocalGameSavePaths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return False

# Import local game save
def ImportLocalGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if save can be unpacked
    if not CanSaveBeUnpacked(game_info):
        return True

    # Unpack save
    success = UnpackSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

# Export local game save
def ExportLocalGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Pack save
    success = PackSave(
        game_info = game_info,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

############################################################

# Import game save paths
def ImportGameSavePaths(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return ImportStoreGameSavePaths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return ImportLocalGameSavePaths(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Import all game save paths
def ImportAllGameSavePaths(
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
                    success = ImportGameSavePaths(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

# Import game save
def ImportGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return ImportStoreGameSave(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return ImportLocalGameSave(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Import all game save
def ImportAllGameSaves(
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
                    success = ImportGameSave(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

# Export game save
def ExportGameSave(
    game_info,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if stores.IsStorePlatform(game_info.get_platform()):
        return ExportStoreGameSave(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return ExportLocalGameSave(
            game_info = game_info,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Export all game save
def ExportAllGameSave(
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
                    success = ExportGameSave(
                        game_info = game_info,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                    if not success:
                        return False

    # Should be successful
    return True

############################################################
