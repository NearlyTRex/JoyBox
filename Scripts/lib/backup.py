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
import hashing
import lockerinfo

# Resolve path
def resolve_path(
    path = None,
    source_type = None,
    base_path = None,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_offset = None):

    # Use existing path if it exists (and no base_path override)
    if paths.does_path_exist(path) and not base_path:
        return path

    # Start building resolved path from base_path override or locker root
    if base_path and paths.does_path_exist(base_path):
        resolved_path = base_path
    else:
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
def copy_files_normally(
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
def copy_and_encrypt_files(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = [],
    delete_original = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate passphrase
    if not cryption.is_passphrase_valid(passphrase):
        logger.log_error("Invalid passphrase")
        return False

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        src_dir = paths.get_filename_directory(src_file)
        src_filename = paths.get_filename_file(src_file)
        dest_dir = paths.join_paths(output_base_path, src_dir)

        # Generate encrypted output path
        encrypted_name = cryption.generate_encrypted_filename(src_filename)
        dest_path = paths.join_paths(dest_dir, encrypted_name)

        # Skip if already exists
        if skip_existing and paths.does_path_exist(dest_path):
            logger.log_info("Skipping (exists): '%s'" % dest_path)
            continue

        # Skip if destination decrypts to identical content
        if skip_identical and paths.does_path_exist(dest_path) and not pretend_run:
            tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
                verbose = verbose,
                pretend_run = pretend_run)
            if tmp_dir_success:
                tmp_decrypted = paths.join_paths(tmp_dir_result, src_filename)
                cryption.decrypt_file(
                    src = dest_path,
                    passphrase = passphrase,
                    output_file = tmp_decrypted,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if hashing.are_files_identical(
                    first = src_path,
                    second = tmp_decrypted,
                    verbose = verbose,
                    exit_on_failure = False):
                    fileops.remove_directory(
                        src = tmp_dir_result,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = False)
                    logger.log_info("Skipping (identical): '%s'" % dest_path)
                    continue
                fileops.remove_directory(
                    src = tmp_dir_result,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)

        # Ensure destination directory exists
        fileops.make_directory(
            src = dest_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Encrypt the file
        if not pretend_run:
            logger.log_info("Encrypting: '%s' -> '%s'" % (src_path, dest_path))
        success = cryption.encrypt_file(
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
def copy_and_decrypt_files(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = [],
    delete_original = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Validate passphrase
    if not cryption.is_passphrase_valid(passphrase):
        logger.log_error("Invalid passphrase")
        return False

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        src_dir = paths.get_filename_directory(src_file)
        dest_dir = paths.join_paths(output_base_path, src_dir)

        # Get real filename from encrypted file
        if cryption.is_file_encrypted(src_path):
            real_name = cryption.get_embedded_filename(
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
            logger.log_info("Skipping (exists): '%s'" % dest_path)
            continue

        # Skip if decrypted content would be identical to destination
        if skip_identical and paths.does_path_exist(dest_path) and not pretend_run:
            tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
                verbose = verbose,
                pretend_run = pretend_run)
            if tmp_dir_success:
                tmp_decrypted = paths.join_paths(tmp_dir_result, real_name)
                cryption.decrypt_file(
                    src = src_path,
                    passphrase = passphrase,
                    output_file = tmp_decrypted,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if hashing.are_files_identical(
                    first = tmp_decrypted,
                    second = dest_path,
                    verbose = verbose,
                    exit_on_failure = False):
                    fileops.remove_directory(
                        src = tmp_dir_result,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = False)
                    logger.log_info("Skipping (identical): '%s'" % dest_path)
                    continue

                # Files are different - move decrypted temp to destination
                logger.log_info("Updating: '%s'" % dest_path)
                fileops.make_directory(
                    src = dest_dir,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                fileops.move_file_or_directory(
                    src = tmp_decrypted,
                    dest = dest_path,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                fileops.remove_directory(
                    src = tmp_dir_result,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = False)
                if delete_original:
                    fileops.remove_file(
                        src = src_path,
                        verbose = verbose,
                        pretend_run = pretend_run,
                        exit_on_failure = exit_on_failure)
                continue

        # Ensure destination directory exists
        fileops.make_directory(
            src = dest_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Decrypt the file
        if not pretend_run:
            logger.log_info("Decrypting: '%s' -> '%s'" % (src_path, dest_path))
        success = cryption.decrypt_file(
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
def copy_files(
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
        return copy_files_normally(
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
        return copy_and_encrypt_files(
            input_base_path = input_base_path,
            output_base_path = output_base_path,
            passphrase = passphrase,
            exclude_paths = exclude_paths,
            delete_original = delete_original,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Decrypt
    elif cryption_type == config.CryptionType.DECRYPT:
        return copy_and_decrypt_files(
            input_base_path = input_base_path,
            output_base_path = output_base_path,
            passphrase = passphrase,
            exclude_paths = exclude_paths,
            delete_original = delete_original,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return False

# Archive folder
def archive_folder(
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
    success = archive.create_archive_from_folder(
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
def archive_sub_folders(
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
                success = archive.create_archive_from_folder(
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
