# Imports
import os
import os.path
import sys

# Local imports
import config
import command
import programs
import system
import environment

# Setup Google Drive remote
def SetupGoogleDriveRemote(remote_type, verbose = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get create command
    create_cmd = [
        rclone_tool,
        "config",
        "create", remote_type,
        "drive",
        "config_is_local=false"
    ]
    if verbose:
        create_cmd += ["--verbose"]

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Get authorize command
    authorize_cmd = [
        rclone_tool,
        "config",
        "reconnect", "%s:" % remote_type
    ]
    if verbose:
        authorize_cmd += ["--verbose"]

    # Run authorize command
    code = command.RunBlockingCommand(
        cmd = authorize_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Download files from remote
def DownloadFilesFromRemote(local_path, remote_type, remote_path, verbose = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get copy command
    copy_cmd = [
        rclone_tool,
        "copy",
        "%s:%s" % (remote_type, remote_path),
        local_path,
        "--create-empty-src-dirs"
    ]
    if remote_type == config.sync_type_gdrive:
        copy_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if verbose:
        copy_cmd += ["--verbose"]

    # Run copy command
    code = command.RunBlockingCommand(
        cmd = copy_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Upload files to remote
def UploadFilesToRemote(local_path, remote_type, remote_path, verbose = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get copy command
    copy_cmd = [
        rclone_tool,
        "copy",
        local_path,
        "%s:%s" % (remote_type, remote_path),
        "--create-empty-src-dirs"
    ]
    if remote_type == config.sync_type_gdrive:
        copy_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if verbose:
        copy_cmd += ["--verbose"]

    # Run copy command
    code = command.RunBlockingCommand(
        cmd = copy_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Sync files from remote
def SyncFilesFromRemote(local_path, remote_type, remote_path, verbose = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        "%s:%s" % (remote_type, remote_path),
        local_path,
        "--create-empty-src-dirs"
    ]
    if remote_type == config.sync_type_gdrive:
        sync_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if verbose:
        sync_cmd += ["--verbose"]

    # Run sync command
    code = command.RunBlockingCommand(
        cmd = sync_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Sync files to remote
def SyncFilesToRemote(local_path, remote_type, remote_path, verbose = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        local_path,
        "%s:%s" % (remote_type, remote_path),
        "--create-empty-src-dirs"
    ]
    if remote_type == config.sync_type_gdrive:
        sync_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if verbose:
        sync_cmd += ["--verbose"]

    # Run sync command
    code = command.RunBlockingCommand(
        cmd = sync_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0
