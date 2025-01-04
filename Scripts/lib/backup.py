# Imports
import os, os.path
import sys

# Local imports
import config
import system
import environment
import archive

# Resolve path
def ResolvePath(
    path = None,
    source_type = None,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_offset = None):

    # Use existing path if it exists
    if system.DoesPathExist(path):
        return path

    # Start building resolved path
    resolved_path = environment.GetLockerRootDir(source_type)

    # Augment with gaming categories
    if game_supercategory:
        resolved_path = os.path.join(resolved_path, config.LockerType.GAMING.val(), game_supercategory)
        if game_category:
            resolved_path = os.path.join(resolved_path, game_category)
            if game_subcategory:
                resolved_path = os.path.join(resolved_path, game_subcategory)
                if game_offset:
                    resolved_path = os.path.join(resolved_path, game_offset)

    # Return result
    return resolved_path

# Copy files
def CopyFiles(
    input_base_path,
    output_base_path,
    exclude_paths = [],
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Look at non-excluded dirs in the input base path
    for src_file in system.BuildFileList(input_base_path, excludes = exclude_paths, use_relative_paths = True):

        # Copy files
        success = system.SmartCopy(
            src = os.path.join(input_base_path, src_file),
            dest = os.path.join(output_base_path, src_file),
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Unable to copy backup files from %s to %s" % (input_base_path, output_base_path))
            return False

    # Should be successful
    return True

# Archive files
def ArchiveFiles(
    input_base_path,
    output_base_path,
    archive_type = None,
    exclude_paths = [],
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Select archive type
    if not archive_type:
        archive_type = config.ArchiveFileType.SEVENZIP

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Look at non-excluded dirs in the input base path
    for base_obj in system.GetDirectoryContents(input_base_path, excludes = exclude_paths):
        base_dir = os.path.join(input_base_path, base_obj)
        if system.IsPathDirectory(base_dir):

            # Only look for subdirectories to archive in each main directory
            for sub_obj in system.GetDirectoryContents(base_dir):
                sub_dir = os.path.join(base_dir, sub_obj)
                if not system.IsPathDirectory(sub_dir):
                    continue

                # Get archive info
                archive_basename = sub_obj
                archive_ext = archive_type.cval()

                # Get paths
                tmp_archive_file = os.path.join(tmp_dir_result, archive_basename + "." + archive_ext)
                out_archive_file = os.path.join(output_base_path, base_obj, archive_basename + "." + archive_ext)

                # Archive subdirectory
                success = archive.CreateArchiveFromFolder(
                    archive_file = tmp_archive_file,
                    source_dir = sub_dir,
                    volume_size = "4092m",
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Unable to archive backup files from %s to %s" % (input_base_path, output_base_path))
                    return False

                # Move archive
                success = system.SmartMove(
                    src = tmp_archive_file,
                    dest = out_archive_file,
                    show_progress = show_progress,
                    skip_existing = skip_existing,
                    skip_identical = skip_identical,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    system.LogError("Unable to move archived backup files from %s to %s" % (input_base_path, output_base_path))
                    return False

    # Delete temporary directory
    system.RemoveDirectory(
        dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True
