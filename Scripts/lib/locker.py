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

# Check if path is local
def IsLocalPath(path):
    if path.startswith(environment.get_locker_root_dir(config.SourceType.LOCAL) + config.os_pathsep):
        return True
    if paths.does_path_exist(path):
        return True
    return False

# Check if path is remote
def IsRemotePath(path):
    not IsLocalPath(path)

# Convert to remote path
def ConvertToRemotePath(path):
    old_base_path = environment.get_locker_root_dir(config.SourceType.REMOTE)
    if IsLocalPath(path):
        old_base_path = environment.get_locker_root_dir(config.SourceType.LOCAL)
    return paths.rebase_file_path(
        path = path,
        old_base_path = old_base_path,
        new_base_path = "")

# Convert to local path
def ConvertToLocalPath(path):
    if IsLocalPath(path):
        return path
    return paths.rebase_file_path(
        path = path,
        old_base_path = environment.get_locker_root_dir(config.SourceType.REMOTE),
        new_base_path = environment.get_locker_root_dir(config.SourceType.LOCAL))

# Check if path exists
def DoesRemotePathExist(path, locker_type = None):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Check if path exists
    success = sync.DoesPathExist(
        remote_name = locker_info.get_remote_name(),
        remote_type = locker_info.get_remote_type(),
        remote_path = ConvertToRemotePath(path))
    return success

# Check if path contains files
def DoesRemotePathContainFiles(path, locker_type = None):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Check if path contains files
    success = sync.DoesPathContainFiles(
        remote_name = locker_info.get_remote_name(),
        remote_type = locker_info.get_remote_type(),
        remote_path = ConvertToRemotePath(path))
    return success

# Download path
def DownloadPath(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return (False, "")

    # Get paths
    remote_path = ConvertToRemotePath(src)
    local_path = dest
    if not local_path:
        local_path = ConvertToLocalPath(remote_path)

    # Download files
    success = sync.DownloadFilesFromRemote(
        remote_name = locker_info.get_remote_name(),
        remote_type = locker_info.get_remote_type(),
        remote_path = remote_path,
        local_path = local_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Return result
    return (True, local_path)

# Upload path
def UploadPath(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if not paths.does_path_exist(src, locker_type):
        logger.log_error("Path '%s' does not exist" % src)
        return False

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Get paths
    local_path = src
    remote_path = dest
    if not remote_path:
        if paths.is_path_directory(src):
            remote_path = ConvertToRemotePath(src)
        else:
            remote_path = ConvertToRemotePath(paths.get_filename_directory(src))

    # Upload files
    success = sync.UploadFilesToRemote(
        remote_name = locker_info.get_remote_name(),
        remote_type = locker_info.get_remote_type(),
        remote_path = remote_path,
        local_path = local_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Download and decrypt path
def DownloadAndDecryptPath(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return (False, "")

    # Download files
    success, result = DownloadPath(
        src = src,
        dest = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Decrypt files
    output_files = cryption.DecryptFiles(
        src = result,
        passphrase = locker_info.get_passphrase(),
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(output_files) == 0:
        return (False, "")

    # Return result
    if paths.is_path_file(result) or len(output_files) == 1:
        return (True, output_files[0])
    return (True, result)

# Upload and encrypt path
def UploadAndEncryptPath(
    src,
    dest = None,
    locker_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        logger.log_error("Locker %s not found" % locker_type)
        return False

    # Encrypt files
    output_files = cryption.EncryptFiles(
        src = src,
        passphrase = locker_info.get_passphrase(),
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if len(output_files) == 0:
        return False

    # Upload files
    success = UploadPath(
        src = src,
        dest = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# Get all configured lockers
def GetConfiguredLockers():
    configured = []
    for locker_type in config.LockerType.members():
        if locker_type == config.LockerType.ALL:
            continue
        locker_info = lockerinfo.LockerInfo(locker_type)
        if locker_info and locker_info.get_remote_name():
            if sync.IsRemoteConfigured(
                remote_name = locker_info.get_remote_name(),
                remote_type = locker_info.get_remote_type()):
                configured.append(locker_type)
    return configured

# Upload to single locker
def UploadToLocker(
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
        success = UploadAndEncryptPath(
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
        success = UploadPath(
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
def BackupFiles(
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
    if not sync.IsToolInstalled():
        logger.log_info("Sync tool not installed, skipping upload")
        return True

    # Determine which lockers to upload to
    if locker_type == config.LockerType.ALL:
        lockers_to_upload = GetConfiguredLockers()
        if not lockers_to_upload:
            logger.log_info("No configured lockers found, skipping upload")
            return True
        logger.log_info("Uploading to all configured lockers: %s" % ", ".join(str(l) for l in lockers_to_upload))
    else:
        locker_info = lockerinfo.LockerInfo(locker_type)
        if not locker_info:
            logger.log_error("Locker %s not found" % locker_type)
            return False
        if not sync.IsRemoteConfigured(
            remote_name = locker_info.get_remote_name(),
            remote_type = locker_info.get_remote_type()):
            logger.log_info("Remote not configured for locker %s, skipping upload" % locker_type)
            return True
        lockers_to_upload = [locker_type]

    # Upload to each locker
    for locker in lockers_to_upload:
        success = UploadToLocker(
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
