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

# Backup saves
def BackupSaves(output_path, verbose = False, exit_on_failure = False):

    # Get tool
    save_tool = None
    if programs.IsToolInstalled("Ludusavi"):
        save_tool = programs.GetToolProgram("Ludusavi")
    if not save_tool:
        system.LogError("Ludusavi was not found")
        return False

    # Get backup command
    backup_command = [
        save_tool,
        "--try-manifest-update",
        "backup",
        "--path", os.path.realpath(output_path)
    ]

    # Run backup command
    try:
        command.RunExceptionCommand(
            cmd = backup_command,
            verbose = verbose)
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to backup saves to output path '%s'" % output_path)
            system.LogError(e)
            sys.exit(1)
        return False

    # Check result
    return system.IsDirectoryEmpty(output_path)

# Restore saves
def RestoreSaves(input_path, verbose = False, exit_on_failure = False):

    # Get tool
    save_tool = None
    if programs.IsToolInstalled("Ludusavi"):
        save_tool = programs.GetToolProgram("Ludusavi")
    if not save_tool:
        system.LogError("Ludusavi was not found")
        return False

    # Get restore command
    restore_command = [
        save_tool,
        "--try-manifest-update",
        "restore",
        "--path", os.path.realpath(input_path)
    ]

    # Run restore command
    try:
        command.RunExceptionCommand(
            cmd = restore_command,
            verbose = verbose)
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to restore saves from input path '%s'" % input_path)
            system.LogError(e)
            sys.exit(1)
        return False

    # Should be successful by this point
    return True

# Can individual save be unpacked
def CanSaveBeUnpacked(save_category, save_subcategory, save_name):
    input_save_dir = environment.GetLockerGamingSaveDir(save_category, save_subcategory, save_name)
    output_save_dir = environment.GetCacheGamingSaveDir(save_category, save_subcategory, save_name)
    if not os.path.isdir(input_save_dir) or system.IsDirectoryEmpty(input_save_dir):
        return False
    if os.path.isdir(output_save_dir) and not system.IsDirectoryEmpty(output_save_dir):
        return False
    return True

# Pack individual save
def PackSave(save_category, save_subcategory, save_name, verbose = False, exit_on_failure = False):

    # Get save type
    save_type = None
    if save_category == config.game_category_computer:
        save_type = config.save_type_general

    # Get input save dirs
    input_save_dir = environment.GetCacheGamingSaveDir(save_category, save_subcategory, save_name)
    input_save_type_dir = environment.GetCacheGamingSaveDir(save_category, save_subcategory, save_name, save_type)
    if system.IsDirectoryEmpty(input_save_type_dir) or not system.DoesDirectoryContainFiles(input_save_type_dir):
        return False

    # Get output save dir
    output_save_dir = environment.GetLockerGamingSaveDir(save_category, save_subcategory, save_name)
    system.MakeDirectory(output_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(verbose = verbose)
    if not tmp_dir_success:
        return False

    # Get save archive info
    tmp_save_archive_file = os.path.join(tmp_dir_result, save_name + ".zip")
    out_save_archive_file = os.path.join(output_save_dir, save_name + "_" + str(environment.GetCurrentTimestamp()) + ".zip")

    # Get excludes
    input_excludes = []
    if save_category == config.game_category_computer:
        input_excludes = [config.save_type_wine, config.save_type_sandboxie]

    # Archive save
    success = archive.CreateArchiveFromFolder(
        archive_file = tmp_save_archive_file,
        source_dir = input_save_dir,
        excludes = input_excludes,
        verbose = verbose)
    if not success:
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return False

    # Check if already archived
    found_files = hashing.FindDuplicateArchives(
        filename = tmp_save_archive_file,
        directory = output_save_dir)
    if len(found_files) > 0:
        if verbose:
            system.Log("Save '%s' - '%s' is already packed, skipping ..." % (save_name, save_subcategory))
        system.RemoveDirectory(tmp_dir_result, verbose = verbose)
        return True

    # Move save archive
    success = system.MoveFileOrDirectory(
        src = tmp_save_archive_file,
        dest = out_save_archive_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Upload save archive
    success = locker.UploadPath(
        src = out_save_archive_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Delete temporary directory
    system.RemoveDirectory(tmp_dir_result, verbose = verbose)

    # Check result
    return os.path.exists(out_save_archive_file)

# Pack all saves
def PackSaves(verbose = False, exit_on_failure = False):
    for save_category in config.game_categories:
        for save_subcategory in config.game_subcategories[save_category]:
            save_base_dir = os.path.join(environment.GetCacheGamingSavesRootDir(), save_category, save_subcategory)
            for save_name in system.GetDirectoryContents(save_base_dir):
                success = PackSave(
                    save_category = save_category,
                    save_subcategory = save_subcategory,
                    save_name = save_name,
                    verbose = verbose,
                    exit_on_failure = exit_on_failure)
                if success:
                    if verbose:
                        system.LogSuccess("Packed save '%s' - '%s' successfully" % (save_name, save_subcategory))
                else:
                    return False
    return True

# Unpack individual save
def UnpackSave(save_category, save_subcategory, save_name, verbose = False, exit_on_failure = False):

    # Get input save dir
    input_save_dir = environment.GetLockerGamingSaveDir(save_category, save_subcategory, save_name)
    if system.IsDirectoryEmpty(input_save_dir):
        return False

    # Get output save dir
    output_save_dir = environment.GetCacheGamingSaveDir(save_category, save_subcategory, save_name)
    system.MakeDirectory(output_save_dir, verbose = verbose, exit_on_failure = exit_on_failure)
    if not system.IsDirectoryEmpty(output_save_dir):
        if verbose:
            system.Log("Save '%s' - '%s' is already unpacked, skipping ..." % (save_name, save_subcategory))
        return True

    # Get latest save archive
    archived_save_files = system.BuildFileList(input_save_dir)
    latest_save_archive = archived_save_files[-1]

    # Unpack save archive
    success = archive.ExtractArchive(
        archive_file = latest_save_archive,
        extract_dir = output_save_dir,
        verbose = verbose)
    if not success:
        return False

    # Check result
    return not system.IsDirectoryEmpty(output_save_dir)

# Unpack all saves
def UnpackSaves(verbose = False, exit_on_failure = False):
    for save_category in config.game_categories:
        for save_subcategory in config.game_subcategories[save_category]:
            save_base_dir = os.path.join(environment.GetLockerGamingSavesRootDir(), save_category, save_subcategory)
            for save_name in system.GetDirectoryContents(save_base_dir):
                if CanSaveBeUnpacked(save_category, save_subcategory, save_name):
                    success = UnpackSave(
                        save_category = save_category,
                        save_subcategory = save_subcategory,
                        save_name = save_name,
                        verbose = verbose,
                        exit_on_failure = exit_on_failure)
                    if success:
                        if verbose:
                            system.LogSuccess("Unpacked save '%s' - '%s' successfully" % (save_name, save_subcategory))
                    else:
                        return False
    return True

# Clean empty saves
def CleanEmptySaves(verbose = False, exit_on_failure = False):
    system.RemoveEmptyDirectories(
        dir = environment.GetCacheGamingSavesRootDir(),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    system.RemoveEmptyDirectories(
        dir = environment.GetLockerGamingSavesRootDir(),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

