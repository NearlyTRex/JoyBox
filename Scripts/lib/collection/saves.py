# Imports
import os
import sys

# Local imports
import config
import system
import environment
import archive
import locker
import gameinfo
import stores
import storebase
import saves

############################################################

# Check if save dir is packable
def IsSaveDirPackable(input_save_dir, output_save_dir):
    return system.DoesDirectoryContainFiles(input_save_dir)

# Check if save dir is unpackable
def IsSaveDirUnpackable(input_save_dir, output_save_dir):
    if not system.IsPathDirectory(input_save_dir) or system.IsDirectoryEmpty(input_save_dir):
        return False
    if system.IsPathDirectory(output_save_dir) or not system.IsDirectoryEmpty(output_save_dir):
        return False
    return True

# Can save be packed
def CanSaveBePacked(game_info):
    input_save_dir = game_info.get_save_dir()
    return IsSaveDirPackable(input_save_dir)

# Can save be unpacked
def CanSaveBeUnpacked(game_info):
    input_save_dir = game_info.get_remote_save_dir()
    output_save_dir = game_info.get_save_dir()
    return IsSaveDirUnpackable(input_save_dir, output_save_dir)

############################################################

# Pack save
def PackSave(
    game_info,
    save_dir = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get save dirs
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = game_info.get_save_dir()
    output_save_dir = game_info.get_remote_save_dir()
    if not IsSaveDirPackable(input_save_dir, output_save_dir):
        return False

    # Make output save dir
    system.MakeDirectory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get save archive info
    tmp_save_archive_file = system.JoinPaths(tmp_dir_result, game_info.get_name() + config.ArchiveFileType.ZIP.cval())
    out_save_archive_file = system.JoinPaths(output_save_dir, game_info.get_name() + "_" + str(environment.GetCurrentTimestamp()) + config.ArchiveFileType.ZIP.cval())

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
        system.LogError(
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
        system.LogError(
            message = "Unable to validate save",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Backup archive
    success = locker.BackupFiles(
        src = tmp_save_archive_file,
        dest = out_save_archive_file,
        show_progress = True,
        skip_existing = True,
        skip_identical = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError(
            message = "Unable to backup save",
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

    # Check result
    return system.DoesPathExist(out_save_archive_file)

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
        input_save_dir = game_info.get_remote_save_dir()
    output_save_dir = game_info.get_save_dir()
    if not IsSaveDirUnpackable(input_save_dir, output_save_dir):
        return False

    # Make output save dir
    system.MakeDirectory(
        src = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not system.IsDirectoryEmpty(output_save_dir):
        if verbose:
            system.LogInfo(
                message = "Save already unpacked",
                game_supercategory = game_info.get_supercategory(),
                game_category = game_info.get_category(),
                game_subcategory = game_info.get_subcategory())
        return True

    # Get latest save archive
    archived_save_files = system.BuildFileList(input_save_dir)
    latest_save_archive = archived_save_files[-1] if archived_save_files else None
    if not latest_save_archive:
        return False

    # Unpack save archive
    success = archive.ExtractArchive(
        archive_file = latest_save_archive,
        extract_dir = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError(
            message = "Unable to unpack save",
            game_supercategory = game_info.get_supercategory(),
            game_category = game_info.get_category(),
            game_subcategory = game_info.get_subcategory())
        return False

    # Check result
    return not system.IsDirectoryEmpty(output_save_dir)

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
    paths = store_obj.AddPathVariants(paths)

    # Get translation map
    translation_map = store_obj.BuildPathTranslationMap()

    # Translate paths
    translated_paths = []
    for path in paths:
        for base_key in translation_map.keys():
            for key_replacement in translation_map[base_key]:
                entry = {}
                entry["full"] = path.replace(base_key, key_replacement)
                entry["relative"] = storebase.ConvertFromTokenizedPath(path, store_type = store_obj.GetType())
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
    for archive_file in system.BuildFileList(game_info.get_save_dir()):
        archive_paths = archive.ListArchive(
            archive_file = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        new_paths = []
        for archive_path in archive_paths:
            new_path = storebase.ConvertToTokenizedPath(
                path = archive_path,
                store_type = game_info.get_main_store_type())
            new_paths.append(new_path)
        save_paths += new_paths

    # Update current paths
    save_paths = list(set(save_paths))
    save_paths = system.PruneChildPaths(save_paths)
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
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
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
        if system.DoesDirectoryContainFiles(path_full):
            success = system.SmartCopy(
                src = path_full,
                dest = system.JoinPaths(tmp_dir_result, path_relative),
                show_progress = True,
                skip_existing = True,
                ignore_symlinks = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if success:
                at_least_one_copy = True
    if not at_least_one_copy:
        system.RemoveDirectory(
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
    system.RemoveDirectory(
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

############################################################
