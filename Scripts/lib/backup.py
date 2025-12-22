# Imports
import os, os.path
import sys

# Local imports
import config
import system
import logger
import environment
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
    if system.DoesPathExist(path):
        return path

    # Start building resolved path
    resolved_path = environment.GetLockerRootDir(source_type)

    # Augment with gaming categories
    if game_supercategory:
        resolved_path = system.JoinPaths(resolved_path, config.LockerFolderType.GAMING, game_supercategory)
        if game_category:
            resolved_path = system.JoinPaths(resolved_path, game_category)
            if game_subcategory:
                resolved_path = system.JoinPaths(resolved_path, game_subcategory)
                if game_offset:
                    resolved_path = system.JoinPaths(resolved_path, game_offset)

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
    for src_file in system.BuildFileList(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = system.JoinPaths(input_base_path, src_file)
        dest_path = system.JoinPaths(output_base_path, src_file)

        # Copy file
        success = system.SmartCopy(
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
    for src_file in system.BuildFileList(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = system.JoinPaths(input_base_path, src_file)
        src_dir = system.GetFilenameDirectory(src_file)
        src_filename = system.GetFilenameFile(src_file)
        dest_dir = system.JoinPaths(output_base_path, src_dir)

        # Generate encrypted output path
        encrypted_name = cryption.GenerateEncryptedFilename(src_filename)
        dest_path = system.JoinPaths(dest_dir, encrypted_name)

        # Skip if already exists
        if skip_existing and system.DoesPathExist(dest_path):
            continue

        # Ensure destination directory exists
        system.MakeDirectory(
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
    for src_file in system.BuildFileList(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = system.JoinPaths(input_base_path, src_file)
        src_dir = system.GetFilenameDirectory(src_file)
        dest_dir = system.JoinPaths(output_base_path, src_dir)

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
            real_name = system.GetFilenameFile(src_path)

        # Generate decrypted output path
        dest_path = system.JoinPaths(dest_dir, real_name)

        # Skip if already exists
        if skip_existing and system.DoesPathExist(dest_path):
            continue

        # Ensure destination directory exists
        system.MakeDirectory(
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
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Get archive info
    archive_basename = output_name
    archive_ext = archive_type.cval()

    # Get paths
    tmp_archive_file = system.JoinPaths(tmp_dir_result, archive_basename + archive_ext)
    out_archive_file = system.JoinPaths(output_base_path, base_obj, archive_basename + archive_ext)

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
        system.RemoveDirectoryContents(
            src = output_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Move archive
    success = system.SmartMove(
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
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return system.DoesPathExist(out_archive_file)

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
    tmp_dir_success, tmp_dir_result = system.CreateTemporaryDirectory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Look at non-excluded dirs in the input base path
    for base_obj in system.GetDirectoryContents(input_base_path, excludes = exclude_paths):
        base_dir = system.JoinPaths(input_base_path, base_obj)
        if system.IsPathDirectory(base_dir):

            # Only look for subdirectories to archive in each main directory
            for sub_obj in system.GetDirectoryContents(base_dir):
                sub_dir = system.JoinPaths(base_dir, sub_obj)
                if not system.IsPathDirectory(sub_dir):
                    continue

                # Get archive info
                archive_basename = sub_obj
                archive_ext = archive_type.cval()

                # Get paths
                tmp_archive_file = system.JoinPaths(tmp_dir_result, archive_basename + "." + archive_ext)
                out_archive_file = system.JoinPaths(output_base_path, base_obj, archive_basename + "." + archive_ext)

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
                    system.RemoveDirectoryContents(
                        src = system.JoinPaths(output_base_path, base_obj),
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)

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
                    logger.log_error("Unable to move archived backup files from %s to %s" % (input_base_path, output_base_path))
                    return False

    # Delete temporary directory
    system.RemoveDirectory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Should be successful
    return True
