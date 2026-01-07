# Imports
import os
import os.path
import sys

# Local imports
import config
import sync
import system
import logger
import paths
import environment
import fileops
import cryption
import lockerinfo
import lockerbackend

###########################################################
# Helpers
###########################################################

# Get the default remote locker type (uses primary remote locker)
def get_default_remote_locker():
    return lockerinfo.get_primary_remote_locker_type()

# Check if path is local (exists on local filesystem)
def is_local_path(path):
    local_locker_root = environment.get_locker_root_dir(config.LockerType.LOCAL)
    if local_locker_root and path.startswith(local_locker_root + config.os_pathsep):
        return True
    if paths.does_path_exist(path):
        return True
    return False

# Check if path is remote
def is_remote_path(path):
    return not is_local_path(path)

# Convert to relative path (strips locker root prefix)
def convert_to_relative_path(path, locker_type = None):
    if locker_type is None:
        locker_type = config.LockerType.LOCAL
    locker_root = environment.get_locker_root_dir(locker_type)
    return paths.rebase_file_path(
        path = path,
        old_base_path = locker_root,
        new_base_path = "")

# Convert to local path
def convert_to_local_path(path, source_locker_type = None):
    if is_local_path(path):
        return path
    if source_locker_type is None:
        source_locker_type = get_default_remote_locker()
    source_root = environment.get_locker_root_dir(source_locker_type)
    local_root = environment.get_locker_root_dir(config.LockerType.LOCAL)
    return paths.rebase_file_path(
        path = path,
        old_base_path = source_root,
        new_base_path = local_root)

# Check if path exists on locker
def does_path_exist(path, locker_type = None):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get backend
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Check if path exists on backend
    backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(path, locker_type)
    return backend.path_exists(rel_path)

# Check if path contains files on locker
def does_path_contain_files(path, locker_type = None):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get backend
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Check if path contains files
    backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(path, locker_type)
    return backend.path_contains_files(rel_path)

###########################################################
# Syncing (LOCAL <-> remote, preserves relative paths)
###########################################################

# Sync from remote locker to LOCAL
def sync_from_remote(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return (False, "")

    # Get source backend
    src_backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(src, locker_type)

    # Get destination backend (local locker)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    dest_backend = lockerbackend.get_backend_for_locker(local_info)

    # Determine destination path
    if dest:
        dest_rel_path = dest_backend.get_relative_path(dest)
    else:
        dest_rel_path = rel_path

    # Copy from source to local
    success = dest_backend.sync_from(
        src_backend = src_backend,
        src_rel_path = rel_path,
        dest_rel_path = dest_rel_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Return full local path
    local_path = paths.join_paths(dest_backend.get_root_path(), dest_rel_path)
    return (True, local_path)

# Sync from LOCAL to remote locker
def sync_to_remote(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source path exists locally
    if not paths.does_path_exist(src):
        logger.log_error("Path '%s' does not exist" % src)
        return False

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Get source backend (local)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    src_backend = lockerbackend.get_backend_for_locker(local_info)

    # Get destination backend
    dest_backend = lockerbackend.get_backend_for_locker(locker_info)

    # Determine relative paths
    src_rel_path = src_backend.get_relative_path(src)
    if dest:
        dest_rel_path = dest_backend.get_relative_path(dest)
    else:
        dest_rel_path = src_rel_path

    # Copy from local to destination locker
    success = dest_backend.sync_from(
        src_backend = src_backend,
        src_rel_path = src_rel_path,
        dest_rel_path = dest_rel_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Sync from encrypted remote locker to LOCAL (with decryption)
def sync_from_remote_decrypted(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return (False, "")

    # Get source backend
    src_backend = lockerbackend.get_backend_for_locker(locker_info)
    rel_path = convert_to_relative_path(src, locker_type)

    # Get destination backend (local locker)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    dest_backend = lockerbackend.get_backend_for_locker(local_info)

    # Determine destination path
    if dest:
        dest_rel_path = dest_backend.get_relative_path(dest)
    else:
        dest_rel_path = rel_path

    # Copy from source to local with decryption
    success = dest_backend.sync_from(
        src_backend = src_backend,
        src_rel_path = rel_path,
        dest_rel_path = dest_rel_path,
        cryption_type = config.CryptionType.DECRYPT,
        passphrase = locker_info.get_passphrase(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Return full local path
    local_path = paths.join_paths(dest_backend.get_root_path(), dest_rel_path)
    return (True, local_path)

# Sync from LOCAL to remote locker (with encryption)
def sync_to_remote_encrypted(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source path exists locally
    if not paths.does_path_exist(src):
        logger.log_error("Path '%s' does not exist" % src)
        return False

    # Get locker type
    if locker_type is None:
        locker_type = get_default_remote_locker()

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Get source backend (local)
    local_info = lockerinfo.LockerInfo(config.LockerType.LOCAL)
    src_backend = lockerbackend.get_backend_for_locker(local_info)

    # Get destination backend
    dest_backend = lockerbackend.get_backend_for_locker(locker_info)

    # Determine relative paths
    src_rel_path = src_backend.get_relative_path(src)
    if dest:
        dest_rel_path = dest_backend.get_relative_path(dest)
    else:
        dest_rel_path = src_rel_path

    # Copy from local to destination locker with encryption
    success = dest_backend.sync_from(
        src_backend = src_backend,
        src_rel_path = src_rel_path,
        dest_rel_path = dest_rel_path,
        cryption_type = config.CryptionType.ENCRYPT,
        passphrase = locker_info.get_passphrase(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################
# Copying (arbitrary source to locker)
###########################################################

# Copy from arbitrary source path to a locker
def copy_to_locker(
    src,
    dest_rel_path,
    locker_type,
    skip_existing = False,
    skip_identical = False,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists
    if not paths.does_path_exist(src):
        logger.log_error("Source path '%s' does not exist" % src)
        return False

    # Get destination locker info and backend
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Copy to destination
    dest_backend = lockerbackend.get_backend_for_locker(locker_info)
    return dest_backend.copy_from(
        src_abs_path = src,
        dest_rel_path = dest_rel_path,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        show_progress = show_progress,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy from arbitrary source path to a locker (with encryption)
def copy_to_locker_encrypted(
    src,
    dest_rel_path,
    locker_type,
    skip_existing = False,
    skip_identical = False,
    show_progress = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists
    if not paths.does_path_exist(src):
        logger.log_error("Source path '%s' does not exist" % src)
        return False

    # Get destination locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # For local-only lockers, skip encryption (just do a plain copy)
    if locker_info.is_local_only():
        return copy_to_locker(
            src = src,
            dest_rel_path = dest_rel_path,
            locker_type = locker_type,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Encrypt source to temp file then upload
    passphrase = locker_info.get_passphrase()
    if not passphrase:
        logger.log_warning("No passphrase configured for locker %s, uploading unencrypted" % locker_type)
        return copy_to_locker(
            src = src,
            dest_rel_path = dest_rel_path,
            locker_type = locker_type,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Create temp directory for encrypted file
    temp_dir = fileops.create_temporary_directory()
    try:
        encrypted_file = paths.join_paths(temp_dir, paths.get_filename_file(src) + ".enc")
        success = cryption.encrypt_file(
            src = src,
            passphrase = passphrase,
            output_file = encrypted_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Failed to encrypt file %s" % src)
            return False

        # Upload encrypted file
        encrypted_dest_rel_path = dest_rel_path + ".enc"
        return copy_to_locker(
            src = encrypted_file,
            dest_rel_path = encrypted_dest_rel_path,
            locker_type = locker_type,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            show_progress = show_progress,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    finally:
        fileops.remove_directory(temp_dir)

###########################################################
# Backup (copy source to all configured lockers)
###########################################################

# Get all configured lockers
def get_configured_lockers():
    configured = []
    for locker_type in config.LockerType.members():
        if locker_type == config.LockerType.ALL:
            continue
        locker_info = lockerinfo.LockerInfo(locker_type)
        if not locker_info:
            continue
        if locker_type == config.LockerType.LOCAL:
            if locker_info.get_mount_path() and paths.does_path_exist(locker_info.get_mount_path()):
                configured.append(locker_type)
            continue
        if locker_type == config.LockerType.EXTERNAL:
            if locker_info.get_mount_path() and paths.does_path_exist(locker_info.get_mount_path()):
                configured.append(locker_type)
            continue
        if locker_info.get_name():
            if sync.is_remote_configured(
                remote_name = locker_info.get_name(),
                remote_type = locker_info.get_type()):
                configured.append(locker_type)
    return configured

# Backup source to configured lockers
def backup(
    src,
    dest_rel_path,
    locker_type = None,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    upload_encrypted = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source exists
    if not paths.does_path_exist(src):
        logger.log_error("Source path '%s' does not exist" % src)
        return False

    # Determine which lockers to upload to
    if locker_type is None:
        logger.log_info("No locker type specified, skipping backup")
        return True
    elif locker_type == config.LockerType.ALL:
        lockers_to_upload = get_configured_lockers()
        if not lockers_to_upload:
            logger.log_info("No configured lockers found, skipping backup")
            return True
        logger.log_info("Backing up to all configured lockers: %s" % ", ".join(str(l) for l in lockers_to_upload))
    else:
        lockers_to_upload = [locker_type]

    # Upload to each locker directly from source
    all_success = True
    for locker in lockers_to_upload:
        logger.log_info("Backing up to locker %s..." % locker)
        if upload_encrypted:
            success = copy_to_locker_encrypted(
                src = src,
                dest_rel_path = dest_rel_path,
                locker_type = locker,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            success = copy_to_locker(
                src = src,
                dest_rel_path = dest_rel_path,
                locker_type = locker,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                show_progress = show_progress,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Backup to %s failed" % locker)
            if exit_on_failure:
                return False
            all_success = False
        else:
            logger.log_info("Backup to %s completed" % locker)

    # Delete source afterwards if requested
    if delete_afterwards and all_success:
        fileops.remove_path(src, verbose=verbose, pretend_run=pretend_run)

    # Should be successful
    logger.log_info("Backup completed successfully")
    return all_success
