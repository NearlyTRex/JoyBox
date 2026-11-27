# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import environment
from joybox import fileops
from joybox import filebulk
from joybox import archive
from joybox import cryption
from joybox import hashutil
from joybox import lockerinfo

# The path itself when it exists, else the base path or locker root extended by the given game category folders
def resolve_path(
    path = None,
    locker_type = None,
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
        resolved_path = environment.get_locker_root_dir(locker_type)

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

# Copy every non-excluded file under one folder to the same relative spot under another, without encryption;
# with skip_on_error a failed file is logged and counted instead of stopping the copy
def copy_files_normally(
    input_base_path,
    output_base_path,
    exclude_paths = None,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Init error count
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0

    # Look at non-excluded files in the input base path
    for src_file in paths.build_file_list(input_base_path, excludes = exclude_paths, use_relative_paths = True):
        src_path = paths.join_paths(input_base_path, src_file)
        dest_path = paths.join_paths(output_base_path, src_file)

        # Copy file
        success = filebulk.smart_copy(
            src = src_path,
            dest = dest_path,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = per_file_exit)
        if not success:
            if skip_on_error:
                failed_count += 1
                fileops.report_fileio_error(src_path, dest_path, error_log_path, verbose, pretend_run)
                continue
            logger.log_error("Unable to copy file '%s'" % src_path)
            return False

    # Check errors
    if skip_on_error and failed_count > 0:
        logger.log_warning("copy_files_normally: %d file(s) skipped due to errors%s" % (
            failed_count,
            (" (logged to %s)" % error_log_path) if error_log_path else ""))

    # Should be successful
    return True

# Check an encrypted file decrypts to the same content as a plain one
def does_encrypted_file_match(encrypted_file, plain_file, passphrase, verbose = False):
    with fileops.temporary_directory(verbose = verbose) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_decrypted = paths.join_paths(tmp_dir, paths.get_filename_file(plain_file))
        cryption.decrypt_file(
            src = encrypted_file,
            passphrase = passphrase,
            output_file = tmp_decrypted,
            verbose = verbose,
            exit_on_failure = False)
        return hashutil.are_files_identical(
            first = plain_file,
            second = tmp_decrypted,
            verbose = verbose,
            exit_on_failure = False)

# Decrypt a file over an existing copy of it, leaving the copy alone when it is identical.
# Returns False when there is nowhere to decrypt it to first.
def update_decrypted_file(src_path, dest_path, passphrase, delete_original = False, verbose = False, exit_on_failure = False):
    with fileops.temporary_directory(verbose = verbose) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_decrypted = paths.join_paths(tmp_dir, paths.get_filename_file(dest_path))
        cryption.decrypt_file(
            src = src_path,
            passphrase = passphrase,
            output_file = tmp_decrypted,
            verbose = verbose,
            exit_on_failure = False)
        if hashutil.are_files_identical(first = tmp_decrypted, second = dest_path, verbose = verbose, exit_on_failure = False):
            logger.log_info("Skipping (identical): '%s'" % dest_path)
            return True
        logger.log_info("Updating: '%s'" % dest_path)
        fileops.make_directory(src = paths.get_filename_directory(dest_path), verbose = verbose, exit_on_failure = exit_on_failure)
        fileops.move_file_or_directory(src = tmp_decrypted, dest = dest_path, verbose = verbose, exit_on_failure = exit_on_failure)
    if delete_original:
        fileops.remove_file(src = src_path, verbose = verbose, exit_on_failure = exit_on_failure)
    return True

# Encrypt every non-excluded file under one folder into the same relative spot under another, under an encrypted name
def copy_and_encrypt_files(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = None,
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
            if does_encrypted_file_match(dest_path, src_path, passphrase, verbose = verbose):
                logger.log_info("Skipping (identical): '%s'" % dest_path)
                continue

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

# Decrypt every non-excluded file under one folder into the same relative spot under another, under its embedded real name
def copy_and_decrypt_files(
    input_base_path,
    output_base_path,
    passphrase,
    exclude_paths = None,
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

        # Decrypt over an existing destination only when its content differs
        if skip_identical and paths.does_path_exist(dest_path) and not pretend_run:
            if update_decrypted_file(src_path, dest_path, passphrase, delete_original, verbose, exit_on_failure):
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

# Copy a folder tree plainly, encrypting or decrypting with the locker's passphrase as cryption_type says
def copy_files(
    input_base_path,
    output_base_path,
    cryption_type = None,
    locker_type = None,
    exclude_paths = None,
    delete_original = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
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
            skip_on_error = skip_on_error,
            error_log_path = error_log_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Get passphrase from locker
    passphrase = lockerinfo.LockerInfo(locker_type).get_passphrase()

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
    if cryption_type == config.CryptionType.DECRYPT:
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

# Archive a folder in a temporary directory and move the archive into an output directory,
# clearing that first when asked; failures are logged as backing up between the paths given
def archive_folder_into(
    input_path, output_dir, archive_file_name, failure_paths, exclude_paths = (), clean_output = False,
    show_progress = False, skip_existing = False, skip_identical = False,
    verbose = False, pretend_run = False, exit_on_failure = False):
    with fileops.temporary_directory(verbose = verbose, pretend_run = pretend_run) as tmp_dir:
        if not tmp_dir:
            return False
        tmp_archive_file = paths.join_paths(tmp_dir, archive_file_name)
        if not archive.create_archive_from_folder(
            archive_file = tmp_archive_file,
            source_dir = input_path,
            excludes = exclude_paths,
            volume_size = "4092m",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            logger.log_error("Unable to archive backup files from %s to %s" % failure_paths)
            return False
        if clean_output:
            fileops.remove_directory_contents(src = output_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        if not filebulk.smart_move(
            src = tmp_archive_file,
            dest = paths.join_paths(output_dir, archive_file_name),
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            logger.log_error("Unable to move archived backup files from %s to %s" % failure_paths)
            return False
        return True

# Pack a folder into output_path/output_name as a 7z, or the given type, in 4092 MB volumes; False unless the archive lands
def archive_folder(
    input_path,
    output_path,
    output_name,
    archive_type = None,
    exclude_paths = None,
    clean_output = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get exclude paths
    exclude_paths = [] if exclude_paths is None else exclude_paths

    # Select archive type
    if not archive_type:
        archive_type = config.ArchiveFileType.SEVENZIP

    # Archive, then check the result
    archive_file_name = output_name + archive_type.cval()
    success = archive_folder_into(
        input_path = input_path,
        output_dir = output_path,
        archive_file_name = archive_file_name,
        exclude_paths = exclude_paths,
        clean_output = clean_output,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        failure_paths = (input_path, output_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success and paths.does_path_exist(paths.join_paths(output_path, archive_file_name))

# Pack each second-level folder into its own archive, kept under its top-level folder's name in the output
def archive_sub_folders(
    input_base_path,
    output_base_path,
    archive_type = None,
    exclude_paths = None,
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

    # Archive each subdirectory of each non-excluded main directory
    for base_obj in paths.get_directory_contents(input_base_path, excludes = exclude_paths):
        base_dir = paths.join_paths(input_base_path, base_obj)
        sub_objs = paths.get_directory_contents(base_dir) if paths.is_path_directory(base_dir) else []
        for sub_obj in sub_objs:
            sub_dir = paths.join_paths(base_dir, sub_obj)
            if not paths.is_path_directory(sub_dir):
                continue
            success = archive_folder_into(
                input_path = sub_dir,
                output_dir = paths.join_paths(output_base_path, base_obj),
                archive_file_name = sub_obj + archive_type.cval(),
                clean_output = clean_output,
                show_progress = show_progress,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                failure_paths = (input_base_path, output_base_path),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True
