# Imports
import os
import os.path
import re

# Local imports
import joybox.config as config
import joybox.command as command
import joybox.programs as programs
import joybox.rcloneremotes as rcloneremotes
import joybox.strings as strings
import joybox.logger as logger
import joybox.paths as paths

# Check if tool is installed
def is_tool_installed():
    return programs.is_tool_installed("RClone")

# Get unencrypted remote name
def get_unencrypted_remote_name(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name[:-len("Enc")]
    return remote_name

# Get remote raw type
def get_remote_raw_type(remote_type):
    return config.RemoteType.to_lower_string(remote_type)

# Get remote connection path
def get_remote_connection_path(remote_name, remote_type, remote_path):
    if remote_type == config.RemoteType.B2:
        return "%s:%s%s" % (remote_name, get_unencrypted_remote_name(remote_name), remote_path)
    else:
        return "%s:%s" % (remote_name, remote_path)

# Get common remote flags
def get_common_remote_flags(remote_name, remote_type, remote_action_type, tps_limit = 10, transfers = 1):
    flags = [
        "--fast-list",
        "--tpslimit", str(tps_limit),
        "--transfers", str(transfers),
        "--order-by", "size,ascending"
    ]
    if remote_action_type in config.RemoteActionSyncType.members():
        flags += [
            "--track-renames"
        ]
    if remote_action_type in config.RemoteActionChangeType.members():
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
def get_exclude_flags(excludes):
    flags = []
    if isinstance(excludes, list):
        for exclude in excludes:
            if len(exclude) > 0:
                flags += ["--exclude", exclude]
    elif isinstance(excludes, str) and len(excludes) > 0:
        flags += ["--exclude", excludes]
    return flags

# Run an rclone query, returning its decoded output and exit code
def run_query_command(
    cmd,
    options = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    output, code = command.run_command(
        cmd = cmd,
        options = options,
        capture_output = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if isinstance(output, bytes):
        output = output.decode()
    return (output or "", code)

# Get exclude list with a pattern added, leaving the caller's list untouched
def get_excludes_with(excludes, pattern):
    if excludes is None:
        excludes = []
    elif isinstance(excludes, str):
        excludes = [excludes]
    else:
        excludes = list(excludes)
    if pattern not in excludes:
        excludes.append(pattern)
    return excludes

# Get path MD5
def get_path_md5(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get rclone tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return None

    # Get md5sum command
    md5sum_cmd = [
        rclone_tool,
        "md5sum",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run md5sum command
    md5sum_text, code = run_query_command(
        cmd = md5sum_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return None

    # Get md5 (format: "<32 hex digits>  filename")
    match = re.match(r"\s*([0-9a-fA-F]{32})\s+\S", md5sum_text)
    if match:
        return match.group(1)
    return None

# Get path modification time as timestamp
def get_path_mod_time(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get rclone tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return 0

    # Get lsl command (outputs: size modtime filename)
    lsl_cmd = [
        rclone_tool,
        "lsl",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run lsl command
    lsl_text, code = run_query_command(
        cmd = lsl_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return 0

    # Extract timestamp (format: "  size YYYY-MM-DD HH:MM:SS.nnnnnnnnn filename")
    match = re.match(r"\s*\d+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", lsl_text)
    if match:
        return strings.parse_timestamp(match.group(1))
    return 0

# Check if path matches md5
def does_path_match_md5(
    remote_name,
    remote_type,
    remote_path,
    expected_md5,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get MD5 checksum from remote path
    remote_md5 = get_path_md5(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check match
    if remote_md5 and remote_md5.lower() == expected_md5.lower():
        return True
    return False

# Check if directory exists on remote
def does_directory_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_text, code = run_query_command(
        cmd = list_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check existence
    if code != 0:
        return False
    elif "ERROR" in list_text:
        return False
    elif "error listing" in list_text:
        return False
    elif "directory not found" in list_text:
        return False
    return True

# Check if file exists on remote
def does_file_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Use rclone lsjson to check if specific file exists
    lsjson_cmd = [
        rclone_tool,
        "lsjson",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run lsjson command - returns 0 if file exists, non-zero if not
    options = command.create_command_options()
    options.set_suppress_output(True)
    code = command.run_returncode_command(
        cmd = lsjson_cmd,
        options = rcloneremotes.get_rclone_options([remote_name], options),
        verbose = verbose)
    return code == 0

# Check if path (file or directory) exists on remote
def does_path_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if file exists
    if does_file_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose):
        return True

    # Check if directory exists
    return does_directory_exist(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Check if path contains files
def does_path_contain_files(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get list command
    list_cmd = [
        rclone_tool,
        "lsf",
        "--files-only",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    list_text, code = run_query_command(
        cmd = list_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check if there are any files in the directory
    if code != 0:
        return False
    return len(list_text.strip()) > 0

# Create directory on remote
def create_remote_directory(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        return False

    # Build mkdir command
    mkdir_cmd = [
        rclone_tool,
        "mkdir",
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    if verbose:
        mkdir_cmd += ["--verbose"]

    # Run command, keeping stderr to tell an existing directory from a failure
    output, code = run_query_command(
        cmd = mkdir_cmd,
        options = rcloneremotes.get_rclone_options([remote_name], command.create_command_options(include_stderr = True)),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)
    if code == 0:
        return True
    return "already exist" in output.lower()

# Sync files to remote
def sync_files_to_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    sync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD)
    if pretend_run:
        sync_cmd += ["--dry-run"]
    if verbose:
        sync_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run sync command
    code = command.run_returncode_command(
        cmd = sync_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Move files on remote
def move_files_on_remote(
    remote_name,
    remote_type,
    src_path,
    dest_path,
    files_from = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # A file list that cannot be read must not widen the transfer to everything
    if files_from and not paths.is_path_file(files_from):
        logger.log_error("File list %s does not exist" % files_from)
        return False

    # Build full remote paths
    src_full = get_remote_connection_path(remote_name, remote_type, src_path)
    dest_full = get_remote_connection_path(remote_name, remote_type, dest_path)

    # Build move command
    move_cmd = [
        rclone_tool,
        "move",
        src_full,
        dest_full
    ]
    if files_from:
        move_cmd += ["--files-from", files_from]
    if pretend_run:
        move_cmd += ["--dry-run"]
    if verbose:
        move_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run move command
    code = command.run_returncode_command(
        cmd = move_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Purge path on remote
def purge_path_on_remote(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build full remote path
    remote_full = get_remote_connection_path(remote_name, remote_type, remote_path)

    # Build purge command
    purge_cmd = [
        rclone_tool,
        "purge",
        remote_full
    ]
    if pretend_run:
        purge_cmd += ["--dry-run"]
    if verbose:
        purge_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run purge command
    code = command.run_returncode_command(
        cmd = purge_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Delete single file on remote
def delete_file_on_remote(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build full remote path
    remote_full = get_remote_connection_path(remote_name, remote_type, remote_path)

    # Build deletefile command
    delete_cmd = [
        rclone_tool,
        "deletefile",
        remote_full
    ]
    if pretend_run:
        delete_cmd += ["--dry-run"]
    if verbose:
        delete_cmd += ["--verbose"]

    # Run delete command
    code = command.run_returncode_command(
        cmd = delete_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Move files to recycle bin on remote
def recycle_files_on_remote(
    remote_name,
    remote_type,
    remote_path,
    files_from,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Without a file list the move would take the whole path into the bin
    if not files_from:
        logger.log_error("Recycling needs a list of files")
        return False

    # Get recycle bin path on remote
    recycle_bin_path = os.path.join(remote_path, recycle_folder).replace("\\", "/")

    # Move files to recycle bin
    return move_files_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        src_path = remote_path,
        dest_path = recycle_bin_path,
        files_from = files_from,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Empty recycle bin on remote
def empty_recycle_bin(
    remote_name,
    remote_type,
    remote_path,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get recycle bin path on remote
    recycle_bin_path = os.path.join(remote_path, recycle_folder).replace("\\", "/")

    # Purge recycle bin
    return purge_path_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = recycle_bin_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Pull files from remote
def pull_files_from_remote(
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
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        get_remote_connection_path(remote_name, remote_type, remote_path),
        local_path
    ]
    sync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PULL)
    sync_cmd += get_exclude_flags(excludes)
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
    code = command.run_returncode_command(
        cmd = sync_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Push files to remote
def push_files_to_remote(
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
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get sync command
    sync_cmd = [
        rclone_tool,
        "sync",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    sync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PUSH)
    sync_cmd += get_exclude_flags(excludes)
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
    code = command.run_returncode_command(
        cmd = sync_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Merge files both ways
def merge_files_both_ways(
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
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Get bisync command
    bisync_cmd = [
        rclone_tool,
        "bisync",
        local_path,
        get_remote_connection_path(remote_name, remote_type, remote_path),
        "--check-access"
    ]
    bisync_cmd += get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.MERGE)
    bisync_cmd += get_exclude_flags(excludes)
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
    code = command.run_returncode_command(
        cmd = bisync_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Copy file from one remote to another
def copy_remote_to_remote(
    src_remote_name,
    src_remote_type,
    src_remote_path,
    dest_remote_name,
    dest_remote_type,
    dest_remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return False

    # Build source and dest paths
    src_full = get_remote_connection_path(src_remote_name, src_remote_type, src_remote_path)
    dest_full = get_remote_connection_path(dest_remote_name, dest_remote_type, dest_remote_path)

    # Build copyto command
    copyto_cmd = [
        rclone_tool,
        "copyto",
        src_full,
        dest_full
    ]
    if pretend_run:
        copyto_cmd += ["--dry-run"]
    if verbose:
        copyto_cmd += ["--verbose", "--progress"]

    # Run copyto command
    code = command.run_returncode_command(
        cmd = copyto_cmd,
        options = rcloneremotes.get_rclone_options([src_remote_name, dest_remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0
