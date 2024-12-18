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
import hashing
import locker

# Can individual save be unpacked
def CanSaveBeUnpacked(
    game_category,
    game_subcategory,
    game_name):
    input_save_dir = environment.GetLockerGamingSaveDir(game_category, game_subcategory, game_name)
    output_save_dir = environment.GetCacheGamingSaveDir(game_category, game_subcategory, game_name)
    if not os.path.isdir(input_save_dir) or system.IsDirectoryEmpty(input_save_dir):
        return False
    if os.path.isdir(output_save_dir) and not system.IsDirectoryEmpty(output_save_dir):
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
    tmp_save_archive_file = os.path.join(tmp_dir_result, game_name + ".zip")
    out_save_archive_file = os.path.join(output_save_dir, game_name + "_" + str(environment.GetCurrentTimestamp()) + ".zip")

    # Get excludes
    input_excludes = []
    if game_category == config.game_category_computer:
        input_excludes = [config.save_type_wine, config.save_type_sandboxie]

    # Archive save
    success = archive.CreateArchiveFromFolder(
        archive_file = tmp_save_archive_file,
        source_dir = input_save_dir,
        excludes = input_excludes,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return False

    # Check if already archived
    found_files = hashing.FindDuplicateArchives(
        filename = tmp_save_archive_file,
        directory = output_save_dir)
    if len(found_files) > 0:
        if verbose:
            system.Log("Save '%s' - '%s' is already packed, skipping ..." % (game_name, game_subcategory))
        system.RemoveDirectory(
            dir = tmp_dir_result,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return True

    # Move save archive
    success = system.MoveFileOrDirectory(
        src = tmp_save_archive_file,
        dest = out_save_archive_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload save archive
    success = locker.UploadPath(
        src = out_save_archive_file,
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
            system.Log("Save '%s' - '%s' is already unpacked, skipping ..." % (game_name, game_subcategory))
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
    if game_category == config.game_category_computer:

        # Create user folders
        for user_folder in config.computer_user_folders:
            user_path = os.path.join(save_dir, config.save_type_general, user_folder)
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
    tmp_dir_extract = os.path.join(tmp_dir_result, "extract")
    tmp_dir_archive = os.path.join(tmp_dir_result, "archive")
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
        archive_file = os.path.join(tmp_dir_archive, system.GetFilenameFile(save_archive)),
        source_dir = tmp_dir_extract,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Replace archive
    success = system.TransferFile(
        src = os.path.join(tmp_dir_archive, system.GetFilenameFile(save_archive)),
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
