# Imports
import os
import os.path
import sys

# Local imports
import config
import sync
import system
import environment
import ini

# Convert to relative path
def ConvertToRelativePath(path):
    return system.RebaseFilePath(path, environment.GetLockerRootDir(), "")

# Download file
def DownloadFile(
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if os.path.isabs(path):
        system.LogError("Path '%s' is not a relative path" % path)
        return False

    # Get sync options
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
    return success

# Upload file
def UploadFile(
    path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check path
    if not system.DoesPathExist():
        system.LogError("Path '%s' does not exist" % path)
        return False

    # Get sync options
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
