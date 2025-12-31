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

# Download path from locker to local
def download_path(
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
    success = dest_backend.copy_file_from(
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

# Upload path from local to locker
def upload_path(
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
    success = dest_backend.copy_file_from(
        src_backend = src_backend,
        src_rel_path = src_rel_path,
        dest_rel_path = dest_rel_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Download and decrypt path from encrypted locker to local
def download_and_decrypt_path(
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
    success = dest_backend.copy_file_from(
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

# Upload and encrypt path from local to encrypted locker
def upload_and_encrypt_path(
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

    # Copy from local to destination with encryption
    success = dest_backend.copy_file_from(
        src_backend = src_backend,
        src_rel_path = src_rel_path,
        dest_rel_path = dest_rel_path,
        cryption_type = config.CryptionType.ENCRYPT,
        passphrase = locker_info.get_passphrase(),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Get all configured lockers
def get_configured_lockers():
    configured = []
    for locker_type in config.LockerType.members():
        if locker_type == config.LockerType.ALL:
            continue
        if locker_type == config.LockerType.LOCAL:
            continue
        locker_info = lockerinfo.LockerInfo(locker_type)
        if not locker_info:
            continue
        if locker_info.get_remote_name():
            if sync.is_remote_configured(
                remote_name = locker_info.get_remote_name(),
                remote_type = locker_info.get_remote_type()):
                configured.append(locker_type)
        elif locker_type == config.LockerType.EXTERNAL:
            if locker_info.get_local_path() and paths.does_path_exist(locker_info.get_local_path()):
                configured.append(locker_type)
    return configured

# Upload to single locker
def upload_to_locker(
    dest,
    locker_type,
    upload_encrypted = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Upload encrypted files
    logger.log_info("Uploading to locker %s..." % locker_type)
    if upload_encrypted:
        logger.log_info("Uploading encrypted files to %s..." % locker_type)
        success = upload_and_encrypt_path(
            src = dest,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Encrypted upload to %s failed" % locker_type)
            return False
        logger.log_info("Encrypted upload to %s completed" % locker_type)

    # Upload plain files
    else:
        logger.log_info("Uploading plain files to %s..." % locker_type)
        success = upload_path(
            src = dest,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            logger.log_error("Plain upload to %s failed" % locker_type)
            return False
        logger.log_info("Plain upload to %s completed" % locker_type)
    return True

# Backup files
def backup_files(
    src,
    dest,
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

    # Transfer files
    logger.log_info(f"Starting file transfer from {src} to {dest}")
    if paths.is_path_directory(src):
        src_files = paths.get_directory_contents(src)
        logger.log_info(f"Source directory contains {len(src_files)} items")
    success = fileops.smart_transfer(
        src = src,
        dest = dest,
        delete_afterwards = delete_afterwards,
        show_progress = show_progress,
        skip_existing = skip_existing,
        skip_identical = skip_identical,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error(f"File transfer failed from {src} to {dest}")
        return False
    logger.log_info("File transfer completed successfully")

    # Upload files
    logger.log_info("Checking if sync tool is installed...")
    if not sync.is_tool_installed():
        logger.log_info("Sync tool not installed, skipping upload")
        return True

    # Determine which lockers to upload to
    if locker_type == config.LockerType.ALL:
        lockers_to_upload = get_configured_lockers()
        if not lockers_to_upload:
            logger.log_info("No configured lockers found, skipping upload")
            return True
        logger.log_info("Uploading to all configured lockers: %s" % ", ".join(str(l) for l in lockers_to_upload))
    else:
        locker_info = lockerinfo.LockerInfo(locker_type)
        if not locker_info:
            logger.log_error("Locker %s not found" % locker_type)
            return False
        if not sync.is_remote_configured(
            remote_name = locker_info.get_remote_name(),
            remote_type = locker_info.get_remote_type()):
            logger.log_info("Remote not configured for locker %s, skipping upload" % locker_type)
            return True
        lockers_to_upload = [locker_type]

    # Upload to each locker
    for locker in lockers_to_upload:
        success = upload_to_locker(
            dest = dest,
            locker_type = locker,
            upload_encrypted = upload_encrypted,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success and exit_on_failure:
            return False

    # Should be successful
    logger.log_info("BackupFiles completed successfully")
    return True
