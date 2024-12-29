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
import ini

# Check if path is remote
def IsRemotePath(path):
    if system.DoesPathExist(path):
        return False
    if os.path.isabs(path):
        return False
    return True

# Check if path is local
def IsLocalPath(path):
    return not IsRemotePath(path)

# Convert to remote path
def ConvertToRemotePath(path):
    if IsRemotePath(path):
        return path
    return system.RebaseFilePath(
        path = path,
        old_base_path = environment.GetLockerRootDir(config.SourceType.LOCAL),
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
def DoesRemotePathExist(path):

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Check if path exists
    success = sync.DoesPathExist(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
        remote_path = ConvertToRemotePath(path))
    return success

# Check if path contains files
def DoesRemotePathContainFiles(path):

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Check if path contains files
    success = sync.DoesPathContainFiles(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
        remote_path = ConvertToRemotePath(path))
    return success

# Download path
def DownloadPath(
    src,
    dest = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Get paths
    remote_path = ConvertToRemotePath(src)
    local_path = dest
    if not local_path:
        local_path = ConvertToLocalPath(remote_path)

    # Download files
    success = sync.DownloadFilesFromRemote(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if not system.DoesPathExist(src):
        system.LogError("Path '%s' does not exist" % src)
        return False

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Get paths
    local_path = src
    remote_path = dest
    if not remote_path:
        remote_path = ConvertToRemotePath(system.GetFilenameDirectory(src))

    # Upload files
    success = sync.UploadFilesToRemote(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get options
    locker_passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

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
    output_files = []
    for file in system.BuildFileList(result):
        output_file = cryption.GetRealFilePath(
            source_file = file,
            passphrase = locker_passphrase,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        success = cryption.DecryptFile(
            source_file = file,
            output_file = output_file,
            passphrase = locker_passphrase,
            delete_original = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if success:
            output_files.append(output_file)
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get options
    locker_passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Encrypt files
    output_files = []
    for file in system.BuildFileList(src):
        output_file = cryption.GenerateEncryptedFilename(file)
        success = cryption.EncryptFile(
            source_file = file,
            output_file = output_file,
            passphrase = locker_passphrase,
            delete_original = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if success:
            output_files.append(output_file)
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

# Backup files
def BackupFiles(
    src,
    dest,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    upload_encrypted = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Transfer files
    success = system.TransferFile(
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
        return False

    # Upload files
    if sync.IsToolInstalled():

        # Check if remote configured
        if sync.IsRemoteConfigured(
            remote_name = locker_remote_name,
            remote_type = locker_remote_type):

            # Upload encryped files
            if upload_encrypted:
                success = UploadAndEncryptPath(
                    src = dest,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

            # Upload plain files
            else:
                success = UploadPath(
                    src = dest,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
                if not success:
                    return False

    # Should be successful
    return True
