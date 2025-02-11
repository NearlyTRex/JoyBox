# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import environment
import programs
import archive
import locker
import gameinfo
import jsondata
import storebase

# Can individual save be unpacked
def CanSaveBeUnpacked(
    game_category,
    game_subcategory,
    game_name):
    input_save_dir = environment.GetLockerGamingSaveDir(game_category, game_subcategory, game_name)
    output_save_dir = environment.GetCacheGamingSaveDir(game_category, game_subcategory, game_name)
    if not system.IsPathDirectory(input_save_dir) or system.IsDirectoryEmpty(input_save_dir):
        return False
    if system.IsPathDirectory(output_save_dir) and not system.IsDirectoryEmpty(output_save_dir):
        return False
    return True

# Pack individual save
def PackSave(
    game_category,
    game_subcategory,
    game_name,
    save_dir = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get input save dir
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = environment.GetCacheGamingSaveDir(game_category, game_subcategory, game_name)
    if system.IsDirectoryEmpty(input_save_dir) or not system.DoesDirectoryContainFiles(input_save_dir):
        return False

    # Get output save dir
    output_save_dir = environment.GetLockerGamingSaveDir(game_category, game_subcategory, game_name)
    system.MakeDirectory(
        dir = output_save_dir,
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
    tmp_save_archive_file = system.JoinPaths(tmp_dir_result, game_name + config.ArchiveFileType.ZIP.cval())
    out_save_archive_file = system.JoinPaths(output_save_dir, game_name + "_" + str(environment.GetCurrentTimestamp()) + config.ArchiveFileType.ZIP.cval())

    # Get excludes
    input_excludes = []
    if game_category == config.Category.COMPUTER:
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
        system.LogError("Unable to archive save for '%s' - '%s' - '%s'" % (game_category, game_subcategory, game_name))
        return False

    # Test archive
    success = archive.TestArchive(
        archive_file = tmp_save_archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to validate save for '%s' - '%s' - '%s'" % (game_category, game_subcategory, game_name))
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
        system.LogError("Unable to backup save for '%s' - '%s' - '%s'" % (game_category, game_subcategory, game_name))
        return False

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(out_save_archive_file)

# Unpack individual save
def UnpackSave(
    game_category,
    game_subcategory,
    game_name,
    save_dir = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get input save dir
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = environment.GetLockerGamingSaveDir(game_category, game_subcategory, game_name)
    if system.IsDirectoryEmpty(input_save_dir) or not system.DoesDirectoryContainFiles(input_save_dir):
        return False

    # Get output save dir
    output_save_dir = environment.GetCacheGamingSaveDir(game_category, game_subcategory, game_name)
    system.MakeDirectory(
        dir = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not system.IsDirectoryEmpty(output_save_dir):
        if verbose:
            system.LogInfo("Save already unpacked for '%s' - '%s' - '%s'" % (game_category, game_subcategory, game_name))
        return True

    # Get latest save archive
    archived_save_files = system.BuildFileList(input_save_dir)
    latest_save_archive = archived_save_files[-1]

    # Unpack save archive
    success = archive.ExtractArchive(
        archive_file = latest_save_archive,
        extract_dir = output_save_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to unpack save for '%s' - '%s' - '%s'" % (game_category, game_subcategory, game_name))
        return False

    # Check result
    return not system.IsDirectoryEmpty(output_save_dir)

# Normalize save dir
def NormalizeSaveDir(
    game_category,
    game_subcategory,
    game_name,
    save_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Computer
    if game_category == config.Category.COMPUTER:

        # Create user folders
        for user_folder in config.computer_user_folders:
            user_path = system.JoinPaths(save_dir, config.SaveType.GENERAL, user_folder)
            if not os.path.exists(user_path):
                success = system.MakeDirectory(
                    dir = user_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

    # Must be successful
    return True

# Normalize save archive
def NormalizeSaveArchive(
    game_category,
    game_subcategory,
    game_name,
    save_archive,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Make temporary dirs
    tmp_dir_extract = system.JoinPaths(tmp_dir_result, "extract")
    tmp_dir_archive = system.JoinPaths(tmp_dir_result, "archive")
    system.MakeDirectory(
        dir = tmp_dir_extract,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.MakeDirectory(
        dir = tmp_dir_archive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Extract archive
    success = archive.ExtractArchive(
        archive_file = save_archive,
        extract_dir = tmp_dir_extract,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Normalize save dir
    success = NormalizeSaveDir(
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name,
        save_dir = tmp_dir_extract,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Create archive
    success = archive.CreateArchiveFromFolder(
        archive_file = system.JoinPaths(tmp_dir_archive, system.GetFilenameFile(save_archive)),
        source_dir = tmp_dir_extract,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Replace archive
    success = system.SmartTransfer(
        src = system.JoinPaths(tmp_dir_archive, system.GetFilenameFile(save_archive)),
        dest = save_archive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(save_archive)

# Import save paths
def ImportSavePaths(
    game_category,
    game_subcategory,
    game_name,
    save_dir = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Ignore non-computer categories
    if game_category != config.Category.COMPUTER:
        return True

    # Get input save dir
    input_save_dir = save_dir
    if not input_save_dir:
        input_save_dir = environment.GetLockerGamingSaveDir(game_category, game_subcategory, game_name)
    if system.IsDirectoryEmpty(input_save_dir) or not system.DoesDirectoryContainFiles(input_save_dir):
        return True

    # Get json file
    json_file = environment.GetJsonMetadataFile(
        game_supercategory = config.Supercategory.ROMS,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name)
    if not system.IsPathFile(json_file):
        return False

    # Get game info
    game_info = gameinfo.GameInfo(
        json_file = json_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get store key
    store_key = game_info.get_main_store_key()
    if not store_key:
        return False

    # Get store type
    store_type = game_info.get_main_store_type()

    # Get current jsondata
    current_jsondata = game_info.read_wrapped_json_data(
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not current_jsondata:
        return False

    # Get current paths
    save_paths = current_jsondata.get_subvalue(store_key, config.json_key_store_paths)

    # Read save files and add paths
    for archive_file in system.BuildFileList(input_save_dir):
        archive_paths = archive.ListArchive(
            archive_file = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        new_paths = []
        for archive_path in archive_paths:
            new_path = storebase.ConvertToTokenizedPath(
                path = archive_path,
                store_type = store_type)
            new_paths.append(new_path)
        save_paths += new_paths

    # Update current paths
    save_paths = list(set(save_paths))
    save_paths = system.PruneChildPaths(save_paths)
    current_jsondata.set_subvalue(store_key, config.json_key_store_paths, save_paths)

    # Write back changes
    success = game_info.write_wrapped_json_data(
        json_wrapper = current_jsondata,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success
