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

    # Download path
    success, result = DownloadPath(
        src = src,
        dest = dest,
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
