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

# Convert to relative path
def ConvertToRelativePath(path, source_type = None):
    return system.RebaseFilePath(path, environment.GetLockerRootDir(source_type), "")

# Check if path exists
def DoesPathExist(path, source_type = None):

    # Check path
    if os.path.isabs(path):
        path = ConvertToRelativePath(path, source_type)

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Check if path exists
    success = sync.DoesPathExist(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
        remote_path = path)
    return success

# Check if path contains files
def DoesPathContainFiles(path, source_type = None):

    # Check path
    if os.path.isabs(path):
        path = ConvertToRelativePath(path, source_type)

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")

    # Check if path contains files
    success = sync.DoesPathContainFiles(
        remote_name = locker_remote_name,
        remote_type = locker_remote_type,
        remote_path = path)
    return success

# Download path
def DownloadPath(
    src,
    dest = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if os.path.isabs(src):
        src = ConvertToRelativePath(src)

    # Get options
    locker_remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    locker_remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")
    locker_local_path = ini.GetIniPathValue("UserData.Share", "locker_local_path")

    # Get paths
    remote_path = src
    local_path = dest
    if not local_path:
        local_path = os.path.join(locker_local_path, src)

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
    for file in system.BuildFileList(result):
        success = cryption.DecryptFile(
            source_file = file,
            output_file = cryption.GetDecryptedFilename(file),
            passphrase = locker_passphrase,
            delete_original = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return (False, "")

    # Return result
    if os.path.isfile(result):
        return (True, cryption.GetDecryptedFilename(result))
    return (True, result)

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
        remote_path = system.GetFilenameDirectory(ConvertToRelativePath(src))

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

# Encrypt and upload path
def EncryptAndUploadPath(
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
    locker_passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Get paths
    local_path = src
    remote_path = dest
    if not remote_path:
        remote_path = system.GetFilenameDirectory(ConvertToRelativePath(src))

    # Encrypt files
    for file in system.BuildFileList(src):
        encrypted_file = cryption.GetEncryptedFilename(file)
        success = cryption.EncryptFile(
            source_file = file,
            output_file = encrypted_file,
            passphrase = locker_passphrase,
            delete_original = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

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

# Copy files
def CopyFiles(
    src,
    dest = None,
    source_type = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Copy files
    if source_type == config.source_type_remote:
        return DownloadAndDecryptPath(
            src = src,
            dest = dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return system.SmartCopy(
            src = src,
            dest = dest,
            show_progress = True,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
