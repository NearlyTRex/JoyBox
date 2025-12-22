# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import paths
import environment
import fileops
import archive
import cryption
import lockerinfo

# Resolve path
def ResolvePath(
    path = None,
    source_type = None,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_offset = None):

    # Use existing path if it exists
    if paths.does_path_exist(path):
        return path

    # Start building resolved path
    resolved_path = environment.get_locker_root_dir(source_type)

    # Augment with gaming categories
    if game_supercategory:
        resolved_path = paths.join_paths(resolved_path, config.LockerFolderType.GAMING, game_supercategory)
        if game_category:
            resolved_path = paths.join_paths(resolved_path, game_category)
            if game_subcategory:
                resolved_path = paths.join_paths(resolved_path, game_subcategory)
                if game_offset:
                    resolved_path = paths.join_paths(resolved_path, game_offset)

    # Return result
    return resolved_path

# Copy files normally
def CopyFilesNormally(
    input_base_path,
    output_base_path,
    exclude_paths = [],
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        dest_path = paths.join_paths(output_base_path, src_file)

        # Copy file
        success = fileops.smart_copy(
            src = src_path,
            dest = dest_path,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to copy file '%s'" % src_path)
            return False

    # Should be successful
    return True

# Copy and encrypt files
def CopyAndEncryptFiles(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = [],
    delete_original = False,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate passphrase
    if not cryption.IsPassphraseValid(passphrase):
        logger.log_error("Invalid passphrase")
        return False

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        src_dir = paths.get_filename_directory(src_file)
        src_filename = paths.get_filename_file(src_file)
        dest_dir = paths.join_paths(output_base_path, src_dir)

        # Generate encrypted output path
        encrypted_name = cryption.GenerateEncryptedFilename(src_filename)
        dest_path = paths.join_paths(dest_dir, encrypted_name)

        # Skip if already exists
        if skip_existing and paths.does_path_exist(dest_path):
            continue

        # Ensure destination directory exists
        fileops.make_directory(
            src = dest_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Encrypt the file
        success = cryption.EncryptFile(
            src = src_path,
            passphrase = passphrase,
            output_file = dest_path,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to encrypt file '%s'" % src_path)
            return False

    # Should be successful
    return True

# Copy and decrypt files
def CopyAndDecryptFiles(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = [],
    delete_original = False,
    skip_existing = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate passphrase
    if not cryption.IsPassphraseValid(passphrase):
        logger.log_error("Invalid passphrase")
        return False

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        src_dir = paths.get_filename_directory(src_file)
        dest_dir = paths.join_paths(output_base_path, src_dir)

        # Get real filename from encrypted file
        if cryption.IsFileEncrypted(src_path):
            real_name = cryption.GetEmbeddedFilename(
                src = src_path,
                passphrase = passphrase,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not real_name:
                logger.log_error("Unable to get embedded filename from '%s'" % src_path)
                return False
        else:
            real_name = paths.get_filename_file(src_path)

        # Generate decrypted output path
        dest_path = paths.join_paths(dest_dir, real_name)

        # Skip if already exists
        if skip_existing and paths.does_path_exist(dest_path):
            continue

        # Ensure destination directory exists
        fileops.make_directory(
            src = dest_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Decrypt the file
        success = cryption.DecryptFile(
            src = src_path,
            passphrase = passphrase,
            output_file = dest_path,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Unable to decrypt file '%s'" % src_path)
            return False

    # Should be successful
    return True

# Copy files
def CopyFiles(
    input_base_path,
    output_base_path,
    cryption_type = None,
    locker_type = None,
    exclude_paths = [],
    delete_original = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Default to no cryption
    if not cryption_type:
        cryption_type = config.CryptionType.NONE

    # Plain copy
    if cryption_type == config.CryptionType.NONE:
        return CopyFilesNormally(
            input_base_path = input_base_path,
            output_base_path = output_base_path,
            exclude_paths = exclude_paths,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get passphrase from locker
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False
    passphrase = locker_info.get_passphrase()

    # Encrypt
    if cryption_type == config.CryptionType.ENCRYPT:
        return CopyAndEncryptFiles(
            input_base_path = input_base_path,
            output_base_path = output_base_path,
            passphrase = passphrase,
            exclude_paths = exclude_paths,
            delete_original = delete_original,
            skip_existing = skip_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Decrypt
    elif cryption_type == config.CryptionType.DECRYPT:
        return CopyAndDecryptFiles(
            input_base_path = input_base_path,
            output_base_path = output_base_path,
            passphrase = passphrase,
            exclude_paths = exclude_paths,
            delete_original = delete_original,
            skip_existing = skip_existing,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return False

# Archive folder
def ArchiveFolder(
    input_path,
    output_path,
    output_name,
    archive_type = None,
    exclude_paths = [],
    clean_output = False,
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
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get archive info
    archive_basename = output_name
    archive_ext = archive_type.cval()

    # Get paths
    tmp_archive_file = paths.join_paths(tmp_dir_result, archive_basename + archive_ext)
    out_archive_file = paths.join_paths(output_base_path, base_obj, archive_basename + archive_ext)

    # Archive files
    success = archive.CreateArchiveFromFolder(
        archive_file = tmp_archive_file,
        source_dir = input_path,
        excludes = exclude_paths,
        volume_size = "4092m",
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to archive backup file from %s to %s" % (input_path, output_path))
        return False

    # Clean output
    if clean_output:
        fileops.remove_directory_contents(
            src = output_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Move archive
    success = fileops.smart_move(
        src = tmp_dir_archive,
        dest = out_archive_file,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to move archived backup file from %s to %s" % (input_path, output_path))
        return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return paths.does_path_exist(out_archive_file)

# Archive sub-folders
def ArchiveSubFolders(
    input_base_path,
    output_base_path,
    archive_type = None,
    exclude_paths = [],
    clean_output = False,
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
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Look at non-excluded dirs in the input base path
    for base_obj in paths.get_directory_contents(input_base_path, excludes = exclude_paths):
        base_dir = paths.join_paths(input_base_path, base_obj)
        if paths.is_path_directory(base_dir):

            # Only look for subdirectories to archive in each main directory
            for sub_obj in paths.get_directory_contents(base_dir):
                sub_dir = paths.join_paths(base_dir, sub_obj)
                if not paths.is_path_directory(sub_dir):
                    continue

                # Get archive info
                archive_basename = sub_obj
                archive_ext = archive_type.cval()

                # Get paths
                tmp_archive_file = paths.join_paths(tmp_dir_result, archive_basename + "." + archive_ext)
                out_archive_file = paths.join_paths(output_base_path, base_obj, archive_basename + "." + archive_ext)

                # Archive subdirectory
                success = archive.CreateArchiveFromFolder(
                    archive_file = tmp_archive_file,
                    source_dir = sub_dir,
                    volume_size = "4092m",
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    logger.log_error("Unable to archive backup files from %s to %s" % (input_base_path, output_base_path))
                    return False

                # Clean output
                if clean_output:
                    fileops.remove_directory_contents(
                        src = paths.join_paths(output_base_path, base_obj),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

                # Move archive
                success = fileops.smart_move(
                    src = tmp_archive_file,
                    dest = out_archive_file,
                    show_progress = show_progress,
                    skip_existing = skip_existing,
                    skip_identical = skip_identical,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    logger.log_error("Unable to move archived backup files from %s to %s" % (input_base_path, output_base_path))
                    return False

    # Delete temporary directory
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True
