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
def ConvertToRelativePath(path):
    return system.RebaseFilePath(path, environment.GetLockerRootDir(), "")

# Download path
def DownloadPath(
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if os.path.isabs(path):
        system.LogError("Path '%s' is not a relative path" % path)
        return (False, "")

    # Get options
    remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")
    remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")
    local_path = ini.GetIniPathValue("UserData.Share", "locker_local_path")

    # Download files
    success = sync.DownloadFilesFromRemote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = path,
        local_path = os.path.join(local_path, path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Return result
    return (True, os.path.join(local_path, path))

# Download and decrypt path
def DownloadAndDecryptPath(
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get options
    locker_passphrase = ini.GetIniValue("UserData.Protection", "locker_passphrase")

    # Download path
    success, result = DownloadPath(
        path = path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return (False, "")

    # Decrypt path
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
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if not system.DoesPathExist():
        system.LogError("Path '%s' does not exist" % path)
        return False

    # Get options
    remote_type = ini.GetIniValue("UserData.Share", "locker_remote_type")
    remote_name = ini.GetIniValue("UserData.Share", "locker_remote_name")

    # Upload files
    success = sync.UploadFilesToRemote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = system.GetFilenameDirectory(ConvertToRelativePath(path)),
        local_path = path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success
