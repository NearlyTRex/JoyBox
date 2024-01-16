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
def DownloadFilesFromRemote(local_path, remote_type, remote_path, interactive = False, verbose = False, pretend_run = False, exit_on_failure = False):

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
    if pretend_run:
        copy_cmd += ["--dry-run"]
    if interactive:
        copy_cmd += ["--interactive"]
    if verbose:
        copy_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run copy command
    code = command.RunBlockingCommand(
        cmd = copy_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Upload files to remote
def UploadFilesToRemote(local_path, remote_type, remote_path, interactive = False, verbose = False, pretend_run = False, exit_on_failure = False):

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
    if pretend_run:
        copy_cmd += ["--dry-run"]
    if interactive:
        copy_cmd += ["--interactive"]
    if verbose:
        copy_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run copy command
    code = command.RunBlockingCommand(
        cmd = copy_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Sync files from remote
def SyncFilesFromRemote(local_path, remote_type, remote_path, interactive = False, verbose = False, pretend_run = False, exit_on_failure = False):

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
    if pretend_run:
        sync_cmd += ["--dry-run"]
    if interactive:
        sync_cmd += ["--interactive"]
    if verbose:
        sync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run sync command
    code = command.RunBlockingCommand(
        cmd = sync_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Sync files to remote
def SyncFilesToRemote(local_path, remote_type, remote_path, interactive = False, verbose = False, pretend_run = False, exit_on_failure = False):

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
    if pretend_run:
        sync_cmd += ["--dry-run"]
    if interactive:
        sync_cmd += ["--interactive"]
    if verbose:
        sync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run sync command
    code = command.RunBlockingCommand(
        cmd = sync_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Sync files both ways
def SyncFilesBothWays(local_path, remote_type, remote_path, resync = False, interactive = False, verbose = False, pretend_run = False, exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get bisync command
    bisync_cmd = [
        rclone_tool,
        "bisync",
        local_path,
        "%s:%s" % (remote_type, remote_path),
        "--check-access",
        "--create-empty-src-dirs"
    ]
    if remote_type == config.sync_type_gdrive:
        bisync_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if resync:
        bisync_cmd += ["--resync"]
    if pretend_run:
        bisync_cmd += ["--dry-run"]
    if interactive:
        bisync_cmd += ["--interactive"]
    if verbose:
        bisync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run bisync command
    code = command.RunBlockingCommand(
        cmd = bisync_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0

# Check files
def CheckFiles(
    local_path,
    remote_type,
    remote_path,
    diff_combined_path = None,
    diff_intersected_path = None,
    diff_missing_src_path = None,
    diff_missing_dest_path = None,
    diff_error_path = None,
    quick = False,
    verbose = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get check command
    check_cmd = [
        rclone_tool,
        "check",
        local_path,
        "%s:%s" % (remote_type, remote_path)
    ]
    if remote_type == config.sync_type_gdrive:
        check_cmd += [
            "--drive-acknowledge-abuse"
        ]
    if system.IsPathValid(diff_combined_path):
        check_cmd += ["--combined", diff_combined_path]
    if system.IsPathValid(diff_intersected_path):
        check_cmd += ["--differ", diff_intersected_path]
    if system.IsPathValid(diff_missing_src_path):
        check_cmd += ["--missing-on-src", diff_missing_src_path]
    if system.IsPathValid(diff_missing_dest_path):
        check_cmd += ["--missing-on-dst", diff_missing_dest_path]
    if system.IsPathValid(diff_error_path):
        check_cmd += ["--error", diff_error_path]
    if quick:
        check_cmd += ["--size-only"]
    if verbose:
        check_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run check command
    code = command.RunBlockingCommand(
        cmd = check_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return code == 0
