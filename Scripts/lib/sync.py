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

# Check if tool is installed
def IsToolInstalled():
    return programs.IsToolInstalled("RClone")

# Get unencrypted remote name
def GetUnencryptedRemoteName(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name[:-len("Enc")]
    return remote_name

# Get encrypted remote name
def GetEncryptedRemoteName(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name
    return "%sEnc" % (remote_name)

# Get remote connection path
def GetRemoteConnectionPath(remote_name, remote_type, remote_path):
    if remote_type == config.RemoteType.B2:
        return "%s:%s%s" % (remote_name, GetUnencryptedRemoteName(remote_name), remote_path)
    else:
        return "%s:%s" % (remote_name, remote_path)

# Get common remote flags
def GetCommonRemoteFlags(remote_name, remote_type, remote_action_type):
    flags = [
        "--fast-list",
        "--tpslimit", "10",
        "--transfers", "1",
        "--order-by", "size,ascending"
    ]
    if remote_action_type in config.RemoteActionSyncTypes:
        flags += [
            "--track-renames"
        ]
    if remote_action_type in config.RemoteActionChangeTypes:
        flags += [
            "--create-empty-src-dirs"
        ]
    if remote_type == config.RemoteType.DRIVE:
        flags += [
            "--drive-acknowledge-abuse",
            "--drive-stop-on-upload-limit",
            "--drive-stop-on-download-limit",
            "--drive-chunk-size", "256M"
        ]
    return flags

# Get exclude flags
def GetExcludeFlags(excludes):
    flags = []
    if isinstance(excludes, list):
        for exclude in excludes:
            if len(exclude) > 0:
                flags += ["--exclude", exclude]
    elif isinstance(excludes, str) and len(excludes) > 0:
        flags += ["--exclude", excludes]
    return flags

# Setup autoconnect remote
def SetupAutoconnectRemote(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        "create", remote_name,
        remote_type.value,
        "config_is_local=false"
    ]
    if verbose:
        create_cmd += ["--verbose"]

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Get authorize command
    authorize_cmd = [
        rclone_tool,
        "config",
        "reconnect", "%s:" % remote_name
    ]
    if verbose:
        authorize_cmd += ["--verbose"]

    # Run authorize command
    code = command.RunBlockingCommand(
        cmd = authorize_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup manual remote
def SetupManualRemote(
    remote_name,
    remote_type,
    remote_config = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        "create", remote_name,
        remote_type.value
    ]
    if isinstance(remote_config, dict):
        for config_key, config_value in remote_config.items():
            create_cmd += ["%s=%s" % (config_key, config_value)]
    if verbose:
        create_cmd += ["--verbose"]

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup encrypted remote
def SetupEncryptedRemote(
    remote_name,
    remote_path,
    remote_encryption_key,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        "create", GetEncryptedRemoteName(remote_name),
        "crypt",
        "remote=%s:" % remote_name,
        "password=%s" % remote_encryption_key
    ]

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Setup remote
def SetupRemote(
    remote_name,
    remote_type,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # B2 requires manual setting
    if remote_type == config.RemoteType.B2:
        return SetupManualRemote(
            remote_type = remote_type,
            remote_name = remote_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Others should use autoconnect
    else:
        return SetupAutoconnectRemote(
            remote_type = remote_type,
            remote_name = remote_name,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Check if path exists
def DoesPathExist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_output = command.RunOutputCommand(
        cmd = list_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check existence
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()
    if "ERROR" in list_text:
        return False
    elif "error listing" in list_text:
        return False
    elif "directory not found" in list_text:
        return False
    return True

# Check if path contains files
def DoesPathContainFiles(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        "--files-only",
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_output = command.RunOutputCommand(
        cmd = list_cmd,
        options = command.CommandOptions(
            blocking_processes = [rclone_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if there are any files in the directory
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()
    return len(list_text.strip()) > 0

# Download files from remote
def DownloadFilesFromRemote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path),
        local_path
    ]
    copy_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DOWNLOAD)
    copy_cmd += GetExcludeFlags(excludes)
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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Upload files to remote
def UploadFilesToRemote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]
    copy_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD)
    copy_cmd += GetExcludeFlags(excludes)
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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Pull files from remote
def PullFilesFromRemote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path),
        local_path
    ]
    sync_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PULL)
    sync_cmd += GetExcludeFlags(excludes)
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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Push files to remote
def PushFilesToRemote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]
    sync_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PUSH)
    sync_cmd += GetExcludeFlags(excludes)
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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Merge files both ways
def MergeFilesBothWays(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    resync = False,
    interactive = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path),
        "--check-access"
    ]
    bisync_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.MERGE)
    bisync_cmd += GetExcludeFlags(excludes)
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
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Diff files
def DiffFiles(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    diff_combined_path = None,
    diff_intersected_path = None,
    diff_missing_src_path = None,
    diff_missing_dest_path = None,
    diff_error_path = None,
    quick = False,
    verbose = False,
    pretend_run = False,
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
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]
    check_cmd += GetCommonRemoteFlags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DIFF)
    check_cmd += GetExcludeFlags(excludes)
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
    command.RunBlockingCommand(
        cmd = check_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Analyze combined output
    if os.path.exists(diff_combined_path):
        count_unchanged = 0
        count_changed = 0
        count_only_dest = 0
        count_only_src = 0
        count_error = 0
        with open(diff_combined_path, "r", encoding="utf8") as f:
            for line in f.readlines():
                if line.startswith("="):
                    count_unchanged += 1
                elif line.startswith("-"):
                    count_only_dest += 1
                elif line.startswith("+"):
                    count_only_src += 1
                elif line.startswith("*"):
                    count_changed += 1
                elif line.startswith("!"):
                    count_error += 1
        system.LogInfo("Number of unchanged files: %d" % count_unchanged)
        system.LogInfo("Number of changed files: %d" % count_changed)
        system.LogInfo("Number of files only on %s%s: %d" % (remote_type, remote_path, count_only_dest))
        system.LogInfo("Number of files only on %s: %d" % (local_path, count_only_src))
        system.LogInfo("Number of error files: %d" % count_error)

# List files
def ListFiles(
    remote_name,
    remote_type,
    remote_path,
    recursive = False,
    only_directories = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get list command
    list_cmd = [rclone_tool]
    if only_directories:
        if recursive:
            list_cmd += ["lsd", "-R"]
        else:
            list_cmd += ["lsd"]
    else:
        if recursive:
            list_cmd += ["ls"]
        else:
            list_cmd += ["ls", "--max-depth", 1]
    list_cmd += [
        GetRemoteConnectionPath(remote_name, remote_type, remote_path)
    ]

    # Run list command
    code = command.RunBlockingCommand(
        cmd = list_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Mount files
def MountFiles(
    remote_name,
    remote_type,
    remote_path,
    mount_path,
    no_cache = False,
    no_checksum = False,
    no_modtime = False,
    no_seek = False,
    read_only = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create mount point
    if environment.IsUnixPlatform():
        system.MakeDirectory(
            dir = mount_path,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if not system.DoesPathExist(mount_path) or not system.IsDirectoryEmpty(mount_path):
            system.LogError("Mount point %s needs to exist and be empty" % mount_path)
            return False

    # Get tool
    rclone_tool = None
    if programs.IsToolInstalled("RClone"):
        rclone_tool = programs.GetToolProgram("RClone")
    if not rclone_tool:
        system.LogError("RClone was not found")
        return False

    # Get mount command
    mount_cmd = [
        rclone_tool,
        "mount"
    ]
    if no_cache:
        mount_cmd += [
            "--vfs-cache-mode", "off"
        ]
    else:
        mount_cmd += [
            "--vfs-cache-mode", "full"
        ]
    mount_cmd += [
        GetRemoteConnectionPath(remote_name, remote_type, remote_path),
        mount_path
    ]
    if environment.IsUnixPlatform():
        mount_cmd += ["--daemon"]
    if no_checksum:
        mount_cmd += ["--no-checksum"]
    if no_modtime:
        mount_cmd += ["--no-modtime"]
    if no_seek:
        mount_cmd += ["--no-seek"]
    if read_only:
        mount_cmd += ["--read-only"]
    if verbose:
        mount_cmd += ["--verbose"]

    # Run mount command
    code = command.RunBlockingCommand(
        cmd = mount_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0
