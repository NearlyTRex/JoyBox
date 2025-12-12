# Imports
import os
import os.path
import sys

# Local imports
import config
import sync
import system
import environment
import cryption
import lockerinfo

# Check if path is local
def IsLocalPath(path):
    if path.startswith(environment.GetLockerRootDir(config.SourceType.LOCAL) + config.os_pathsep):
        return True
    if system.DoesPathExist(path):
        return True
    return False

# Check if path is remote
def IsRemotePath(path):
    not IsLocalPath(path)

# Convert to remote path
def ConvertToRemotePath(path):
    old_base_path = environment.GetLockerRootDir(config.SourceType.REMOTE)
    if IsLocalPath(path):
        old_base_path = environment.GetLockerRootDir(config.SourceType.LOCAL)
    return system.RebaseFilePath(
        path = path,
        old_base_path = old_base_path,
        new_base_path = "")

# Convert to local path
def ConvertToLocalPath(path):
    if IsLocalPath(path):
        return path
    return system.RebaseFilePath(
        path = path,
        old_base_path = environment.GetLockerRootDir(config.SourceType.REMOTE),
        new_base_path = environment.GetLockerRootDir(config.SourceType.LOCAL))

# Check if path exists
def DoesRemotePathExist(path, locker_type = None):

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        system.LogError("Locker %s not found" % locker_type)
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
        system.LogError("Locker %s not found" % locker_type)
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
        system.LogError("Locker %s not found" % locker_type)
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
    if not system.DoesPathExist(src, locker_type):
        system.LogError("Path '%s' does not exist" % src)
        return False

    # Get locker info
    locker_info = lockerinfo.LockerInfo(locker_type)
    if not locker_info:
        system.LogError("Locker %s not found" % locker_type)
        return False

    # Get paths
    local_path = src
    remote_path = dest
    if not remote_path:
        if system.IsPathDirectory(src):
            remote_path = ConvertToRemotePath(src)
        else:
            remote_path = ConvertToRemotePath(system.GetFilenameDirectory(src))

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
        system.LogError("Locker %s not found" % locker_type)
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
    if system.IsPathFile(result) or len(output_files) == 1:
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
        system.LogError("Locker %s not found" % locker_type)
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
        system.LogError("Locker %s not found" % locker_type)
        return False

    # Upload encrypted files
    system.LogInfo("Uploading to locker %s..." % locker_type)
    if upload_encrypted:
        system.LogInfo("Uploading encrypted files to %s..." % locker_type)
        success = UploadAndEncryptPath(
            src = dest,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Encrypted upload to %s failed" % locker_type)
            return False
        system.LogInfo("Encrypted upload to %s completed" % locker_type)

    # Upload plain files
    else:
        system.LogInfo("Uploading plain files to %s..." % locker_type)
        success = UploadPath(
            src = dest,
            locker_type = locker_type,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            system.LogError("Plain upload to %s failed" % locker_type)
            return False
        system.LogInfo("Plain upload to %s completed" % locker_type)
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
    system.LogInfo(f"Starting file transfer from {src} to {dest}")
    if system.IsPathDirectory(src):
        src_files = system.GetDirectoryContents(src)
        system.LogInfo(f"Source directory contains {len(src_files)} items")
    success = system.SmartTransfer(
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
        system.LogError(f"File transfer failed from {src} to {dest}")
        return False
    system.LogInfo("File transfer completed successfully")

    # Upload files
    system.LogInfo("Checking if sync tool is installed...")
    if not sync.IsToolInstalled():
        system.LogInfo("Sync tool not installed, skipping upload")
        return True

    # Determine which lockers to upload to
    if locker_type == config.LockerType.ALL:
        lockers_to_upload = GetConfiguredLockers()
        if not lockers_to_upload:
            system.LogInfo("No configured lockers found, skipping upload")
            return True
        system.LogInfo("Uploading to all configured lockers: %s" % ", ".join(str(l) for l in lockers_to_upload))
    else:
        locker_info = lockerinfo.LockerInfo(locker_type)
        if not locker_info:
            system.LogError("Locker %s not found" % locker_type)
            return False
        if not sync.IsRemoteConfigured(
            remote_name = locker_info.get_remote_name(),
            remote_type = locker_info.get_remote_type()):
            system.LogInfo("Remote not configured for locker %s, skipping upload" % locker_type)
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
    system.LogInfo("BackupFiles completed successfully")
    return True
