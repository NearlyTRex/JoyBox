# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import prompts
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
        for folder in (game_category, game_subcategory, game_offset):
            if not folder:
                break
            resolved_path = paths.join_paths(resolved_path, folder)

    # Return result
    return resolved_path

# Copy each non-excluded file to the same relative spot under the output; the number that failed
# and were skipped, or None after logging the first failure when skip_on_error is off
def _copy_tree_files(
    input_base_path, output_base_path, exclude_paths, show_progress, skip_existing, skip_identical,
    skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure):
    per_file_exit = exit_on_failure and not skip_on_error
    failed_count = 0
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
            return None
    return failed_count

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

    # Copy files, counting the skipped ones
    failed_count = _copy_tree_files(
        input_base_path, output_base_path, exclude_paths, show_progress, skip_existing, skip_identical,
        skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure)
    if failed_count is None:
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

# Whether an encrypted destination is kept: it exists and skip_existing is set, or it
# decrypts to the source's content and skip_identical is set
def _is_encrypted_dest_current(dest_path, src_path, passphrase, skip_existing, skip_identical, verbose, pretend_run):

    # Skip if already exists
    if skip_existing and paths.does_path_exist(dest_path):
        logger.log_info("Skipping (exists): '%s'" % dest_path)
        return True

    # Skip if destination decrypts to identical content
    if skip_identical and paths.does_path_exist(dest_path) and not pretend_run:
        if does_encrypted_file_match(dest_path, src_path, passphrase, verbose = verbose):
            logger.log_info("Skipping (identical): '%s'" % dest_path)
            return True
    return False

# Encrypt one file, given relative to the input, into the same spot under the output
# under an encrypted name; False after logging a failed encryption
def _encrypt_tree_file(
    src_file, input_base_path, output_base_path, passphrase, delete_original,
    skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    src_path = paths.join_paths(input_base_path, src_file)
    src_dir = paths.get_filename_directory(src_file)
    src_filename = paths.get_filename_file(src_file)
    dest_dir = paths.join_paths(output_base_path, src_dir)

    # Generate encrypted output path
    encrypted_name = cryption.generate_encrypted_filename(src_filename)
    dest_path = paths.join_paths(dest_dir, encrypted_name)
    if _is_encrypted_dest_current(dest_path, src_path, passphrase, skip_existing, skip_identical, verbose, pretend_run):
        return True

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
        success = _encrypt_tree_file(
            src_file, input_base_path, output_base_path, passphrase, delete_original,
            skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

# The real name embedded in an encrypted file, or a plain file's own name;
# None after logging when the embedded name cannot be read
def _get_decrypted_filename(src_path, passphrase, verbose, exit_on_failure):
    if not cryption.is_file_encrypted(src_path):
        return paths.get_filename_file(src_path)
    real_name = cryption.get_embedded_filename(
        src = src_path,
        passphrase = passphrase,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not real_name:
        logger.log_error("Unable to get embedded filename from '%s'" % src_path)
        return None
    return real_name

# Whether a decrypted destination is done with: it exists and skip_existing is set, or
# skip_identical is set and it was updated in place from a temporary decryption
def _is_decrypted_dest_handled(src_path, dest_path, passphrase, delete_original, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):

    # Skip if already exists
    if skip_existing and paths.does_path_exist(dest_path):
        logger.log_info("Skipping (exists): '%s'" % dest_path)
        return True

    # Decrypt over an existing destination only when its content differs
    if skip_identical and paths.does_path_exist(dest_path) and not pretend_run:
        if update_decrypted_file(src_path, dest_path, passphrase, delete_original, verbose, exit_on_failure):
            return True
    return False

# Decrypt one file, given relative to the input, into the same spot under the output
# under its embedded real name; False after logging a failure
def _decrypt_tree_file(
    src_file, input_base_path, output_base_path, passphrase, delete_original,
    skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    src_path = paths.join_paths(input_base_path, src_file)
    src_dir = paths.get_filename_directory(src_file)
    dest_dir = paths.join_paths(output_base_path, src_dir)

    # Generate decrypted output path
    real_name = _get_decrypted_filename(src_path, passphrase, verbose, exit_on_failure)
    if not real_name:
        return False
    dest_path = paths.join_paths(dest_dir, real_name)
    if _is_decrypted_dest_handled(
        src_path, dest_path, passphrase, delete_original, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
        return True

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
        success = _decrypt_tree_file(
            src_file, input_base_path, output_base_path, passphrase, delete_original,
            skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
        if not success:
            return False

    # Should be successful
    return True

# Encrypt or decrypt a folder tree with the locker's passphrase; False for any other cryption type
def _copy_files_with_cryption(cryption_type, locker_type, delete_original, copy_options):

    # Get passphrase from locker
    passphrase = lockerinfo.LockerInfo(locker_type).get_passphrase()

    # Encrypt
    if cryption_type == config.CryptionType.ENCRYPT:
        return copy_and_encrypt_files(passphrase = passphrase, delete_original = delete_original, **copy_options)

    # Decrypt
    if cryption_type == config.CryptionType.DECRYPT:
        return copy_and_decrypt_files(passphrase = passphrase, delete_original = delete_original, **copy_options)
    return False

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

    # Options every kind of copy takes
    copy_options = {
        "input_base_path": input_base_path,
        "output_base_path": output_base_path,
        "exclude_paths": exclude_paths,
        "skip_existing": skip_existing,
        "skip_identical": skip_identical,
        "verbose": verbose,
        "pretend_run": pretend_run,
        "exit_on_failure": exit_on_failure,
    }

    # Plain copy
    if cryption_type == config.CryptionType.NONE:
        return copy_files_normally(
            show_progress = show_progress, skip_on_error = skip_on_error, error_log_path = error_log_path, **copy_options)

    # Encrypt or decrypt
    return _copy_files_with_cryption(cryption_type, locker_type, delete_original, copy_options)

# The files 7-Zip wrote for an archive: the archive itself, else its .001, .002, ... volumes,
# else the archive name alone so a move of it still reports the missing file
def get_archive_volume_files(archive_file):
    if paths.does_path_exist(archive_file):
        return [archive_file]
    volume_files = []
    while paths.does_path_exist("%s.%03d" % (archive_file, len(volume_files) + 1)):
        volume_files.append("%s.%03d" % (archive_file, len(volume_files) + 1))
    return volume_files or [archive_file]

# Move an archive, or each of its volumes, from the temporary directory into the output directory
def move_archive_volumes(tmp_archive_file, output_dir, show_progress, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    for volume_file in get_archive_volume_files(tmp_archive_file):
        if not filebulk.smart_move(
            src = volume_file,
            dest = paths.join_paths(output_dir, paths.get_filename_file(volume_file)),
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure):
            return False
    return True

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
        if not move_archive_volumes(
            tmp_archive_file, output_dir, show_progress, skip_existing, skip_identical,
            verbose, pretend_run, exit_on_failure):
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
    output_archive_file = paths.join_paths(output_path, archive_file_name)
    return success and (paths.does_path_exist(output_archive_file) or paths.does_path_exist(output_archive_file + ".001"))

# Pack each subfolder of one top-level folder into its own archive under that folder's name
# in the output, emptying the output only before the first; False on the first failure
def _archive_base_folder(
    base_obj, input_base_path, output_base_path, archive_type, clean_output,
    show_progress, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    base_dir = paths.join_paths(input_base_path, base_obj)
    sub_objs = paths.get_directory_contents(base_dir) if paths.is_path_directory(base_dir) else []
    clean_base_output = clean_output
    for sub_obj in sub_objs:
        sub_dir = paths.join_paths(base_dir, sub_obj)
        if not paths.is_path_directory(sub_dir):
            continue
        success = archive_folder_into(
            input_path = sub_dir,
            output_dir = paths.join_paths(output_base_path, base_obj),
            archive_file_name = sub_obj + archive_type.cval(),
            clean_output = clean_base_output,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            failure_paths = (input_base_path, output_base_path),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        clean_base_output = False
    return True

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

    # Archive each subdirectory of each non-excluded main directory, emptying its output only before the first
    for base_obj in paths.get_directory_contents(input_base_path, excludes = exclude_paths):
        success = _archive_base_folder(
            base_obj, input_base_path, output_base_path, archive_type, clean_output,
            show_progress, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
        if not success:
            return False
    return True

# The source root for a backup; quits when it is not a directory
def _resolve_backup_source(path, locker_type, base_path, game_path):
    source_file_root = resolve_path(path = path, locker_type = locker_type, base_path = base_path, **game_path)
    if not paths.is_path_directory(source_file_root):
        logger.log_error("Could not resolve source path", quit_program = True)
    return source_file_root

# The destination root for a backup, made when it lies under an existing locker base; quits
# when it is not a directory otherwise
def _resolve_backup_destination(path, locker_type, base_path, game_path, verbose, pretend_run):
    dest_file_root = resolve_path(path = path, locker_type = locker_type, base_path = base_path, **game_path)
    if not paths.is_path_directory(dest_file_root):
        if base_path and paths.is_path_directory(base_path):
            fileops.make_directory(dest_file_root, verbose = verbose, pretend_run = pretend_run)
        else:
            logger.log_error("Could not resolve destination path", quit_program = True)
    return dest_file_root

# The (source, destination) roots for a backup; quits when either is unusable or they are the same
def _resolve_backup_roots(input_path, output_path, source_locker, dest_locker, input_locker_base, output_locker_base, game_path, verbose, pretend_run):
    source_file_root = _resolve_backup_source(input_path, source_locker, input_locker_base, game_path)
    dest_file_root = _resolve_backup_destination(output_path, dest_locker, output_locker_base, game_path, verbose, pretend_run)
    if paths.are_paths_equal(source_file_root, dest_file_root):
        logger.log_error("Source and destination paths cannot be the same", quit_program = True)
    return source_file_root, dest_file_root

# Preview a backup between two roots; whether the user went ahead
def _confirm_backup_preview(source_file_root, dest_file_root, backup_type, cryption_type):
    details = [
        "Source: %s" % source_file_root,
        "Destination: %s" % dest_file_root,
        "Type: %s" % backup_type
    ]
    if cryption_type != config.CryptionType.NONE:
        details.append("Cryption: %s" % cryption_type)
    if not prompts.prompt_for_preview("Backup files", details):
        logger.log_warning("Operation cancelled by user")
        return False
    return True

# The locker whose passphrase a copy uses: the destination's when encrypting, the source's
# when decrypting, else none
def _get_passphrase_locker(cryption_type, source_locker, dest_locker):
    if cryption_type == config.CryptionType.ENCRYPT:
        return dest_locker
    if cryption_type == config.CryptionType.DECRYPT:
        return source_locker
    return None

# Copy the source tree into the destination, encrypting or decrypting each file; without
# exit_on_failure, failed files are skipped and listed in copy_errors.txt in the destination
def _copy_backup_files(source_file_root, dest_file_root, cryption_type, passphrase_locker, exclude_paths, delete_original, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    skip_on_error = not exit_on_failure
    error_log_path = paths.join_paths(dest_file_root, "copy_errors.txt") if skip_on_error else None
    copy_files(
        input_base_path = source_file_root,
        output_base_path = dest_file_root,
        cryption_type = cryption_type,
        locker_type = passphrase_locker,
        exclude_paths = exclude_paths,
        delete_original = delete_original,
        show_progress = True,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        skip_on_error = skip_on_error,
        error_log_path = error_log_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy the source tree into the destination for a Copy backup, else pack its second-level
# folders into split 7z archives there
def _transfer_backup_files(source_file_root, dest_file_root, backup_type, cryption_type, source_locker, dest_locker, exclude_paths, delete_original, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure):
    if backup_type == config.BackupType.COPY:
        passphrase_locker = _get_passphrase_locker(cryption_type, source_locker, dest_locker)
        _copy_backup_files(
            source_file_root, dest_file_root, cryption_type, passphrase_locker, exclude_paths, delete_original,
            skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
        return
    archive_sub_folders(
        input_base_path = source_file_root,
        output_base_path = dest_file_root,
        archive_type = config.ArchiveFileType.SEVENZIP,
        exclude_paths = exclude_paths,
        show_progress = True,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Resolve the source and destination roots from the paths, locker bases or game folders, then,
# after a preview, copy the source tree across or pack its second-level folders into 7z
# archives; exclude_paths is a comma-separated list of relative path prefixes
def backup_tree(
    input_path = None,
    output_path = None,
    source_locker = None,
    dest_locker = None,
    input_locker_base = None,
    output_locker_base = None,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_offset = None,
    backup_type = config.BackupType.COPY,
    cryption_type = config.CryptionType.NONE,
    exclude_paths = "",
    delete_original = False,
    skip_existing = False,
    skip_identical = False,
    show_preview = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Resolve the roots
    game_path = {
        "game_supercategory": game_supercategory,
        "game_category": game_category,
        "game_subcategory": game_subcategory,
        "game_offset": game_offset}
    source_file_root, dest_file_root = _resolve_backup_roots(
        input_path, output_path, source_locker, dest_locker, input_locker_base, output_locker_base, game_path, verbose, pretend_run)

    # Show preview
    if show_preview and not _confirm_backup_preview(source_file_root, dest_file_root, backup_type, cryption_type):
        return

    # Copy or archive, leaving out the excluded paths
    exclude_list = [p for p in exclude_paths.split(",") if p]
    _transfer_backup_files(
        source_file_root, dest_file_root, backup_type, cryption_type, source_locker, dest_locker, exclude_list,
        delete_original, skip_existing, skip_identical, verbose, pretend_run, exit_on_failure)
