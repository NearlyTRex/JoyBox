# Imports
import os
import os.path
import posixpath
import re

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import rcloneremotes
from joybox import strings
from joybox import logger
from joybox import paths

# Check if tool is installed
def is_tool_installed():
    return programs.is_tool_installed("RClone")

# Remote name with a trailing Enc removed, naming the remote an encrypted one wraps
def get_unencrypted_remote_name(remote_name):
    if remote_name.endswith("Enc"):
        return remote_name[:-len("Enc")]
    return remote_name

# Remote type as the lowercase name rclone uses
def get_remote_raw_type(remote_type):
    return config.RemoteType.to_lower_string(remote_type)

# rclone path for a remote location; B2 paths are prefixed with the bucket named after the unencrypted remote
def get_remote_connection_path(remote_name, remote_type, remote_path):
    if remote_type == config.RemoteType.B2:
        return "%s:%s%s" % (remote_name, get_unencrypted_remote_name(remote_name), remote_path)
    return "%s:%s" % (remote_name, remote_path)

# rclone flags every transfer uses: fast list, rate and transfer limits, smallest first
# plus rename tracking for syncs, empty dirs for changes and Drive quota flags
def get_common_remote_flags(remote_type, remote_action_type, tps_limit = 10, transfers = 1):
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

# --exclude flags for a pattern or list of patterns, skipping empty ones
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

# Get the flags for a dry run, an interactive run and a verbose run, verbose ones showing progress unless told not to
def get_run_flags(pretend_run = False, interactive = False, verbose = False, progress = True):
    flags = []
    if pretend_run:
        flags += ["--dry-run"]
    if interactive:
        flags += ["--interactive"]
    if verbose:
        flags += ["--verbose", "--progress"] if progress else ["--verbose"]
    return flags

# Check a transfer's file list exists; a missing one would widen the transfer to everything
def is_file_list_readable(files_from):
    if files_from and not paths.is_path_file(files_from):
        logger.log_error("File list %s does not exist" % files_from)
        return False
    return True

# Run an rclone command with the named remotes' credentials, returning whether it succeeded
def run_rclone_command(cmd, remote_names, options = None, verbose = False, pretend_run = False, exit_on_failure = False):
    code = command.run_returncode_command(
        cmd = cmd,
        options = rcloneremotes.get_rclone_options(remote_names, options),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Run an rclone transfer over the given paths. The common remote flags are added for an
# action type, then excludes, the file list and extra flags, then the run flags.
def run_transfer(
    subcommand,
    transfer_paths,
    remote_names,
    remote_type = None,
    remote_action_type = None,
    excludes = None,
    files_from = None,
    extra_flags = (),
    interactive = False,
    progress = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool or not is_file_list_readable(files_from):
        return False
    cmd = [rclone_tool, subcommand] + list(transfer_paths)
    if remote_action_type:
        cmd += get_common_remote_flags(
            remote_type = remote_type,
            remote_action_type = remote_action_type)
    cmd += get_exclude_flags(excludes)
    if files_from:
        cmd += ["--files-from", files_from]
    cmd += list(extra_flags)
    cmd += get_run_flags(pretend_run = pretend_run, interactive = interactive, verbose = verbose, progress = progress)
    return run_rclone_command(
        cmd = cmd,
        remote_names = remote_names,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Run an rclone query on a path of a remote, returning its decoded output and exit code,
# or None when rclone is missing
def run_remote_query(
    remote_name,
    remote_type,
    remote_path,
    subcommand,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return None
    return run_query_command(
        cmd = [rclone_tool] + subcommand + [get_remote_connection_path(remote_name, remote_type, remote_path)],
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Get the entry a hash listing keeps for a file
def get_hash_entry(file_path, file_hash, size, mtime):
    return {
        "filename": paths.get_filename_file(file_path),
        "dir": paths.get_filename_directory(file_path),
        "hash": file_hash or "",
        "size": size or 0,
        "mtime": mtime or 0
    }

# MD5 hex digest of a remote file from rclone md5sum; None when the query fails or prints none
def get_path_md5(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Run md5sum
    result = run_remote_query(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        subcommand = ["md5sum"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if result is None or result[1] != 0:
        return None

    # Get md5 (format: "<32 hex digits>  filename")
    match = re.match(r"\s*([0-9a-fA-F]{32})\s+\S", result[0])
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

    # Run lsl (outputs: size modtime filename)
    result = run_remote_query(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        subcommand = ["lsl"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if result is None or result[1] != 0:
        return 0

    # Extract timestamp (format: "  size YYYY-MM-DD HH:MM:SS.nnnnnnnnn filename")
    match = re.match(r"\s*\d+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", result[0])
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
    result = run_remote_query(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        subcommand = ["lsf"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if result is None or result[1] != 0:
        return False
    return not any(marker in result[0] for marker in ("ERROR", "error listing", "directory not found"))

# Check if file exists on remote
def does_file_exist(
    remote_name,
    remote_type,
    remote_path,
    verbose = False):

    # Get tool
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return False

    # Run lsjson, which succeeds only when the file exists
    options = commandbase.create_command_options()
    options.set_suppress_output(True)
    return run_rclone_command(
        cmd = [rclone_tool, "lsjson", get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        options = options,
        verbose = verbose)

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
    result = run_remote_query(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = remote_path,
        subcommand = ["lsf", "--files-only"],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if result is None or result[1] != 0:
        return False
    return len(result[0].strip()) > 0

# Make a directory on the remote with rclone mkdir; True when it already exists, False without rclone
def create_remote_directory(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False):

    # Get tool
    rclone_tool = programs.find_tool_program("RClone", log_missing = False)
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
        options = rcloneremotes.get_rclone_options([remote_name], commandbase.create_command_options(include_stderr = True)),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = False)
    if code == 0:
        return True
    return "already exist" in output.lower()

# Make the remote path match the local path with rclone sync, deleting remote extras
def sync_files_to_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_transfer(
        subcommand = "sync",
        transfer_paths = [local_path, get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Move files between two paths on the same remote, limited to files_from when given
def move_files_on_remote(
    remote_name,
    remote_type,
    src_path,
    dest_path,
    files_from = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_transfer(
        subcommand = "move",
        transfer_paths = [
            get_remote_connection_path(remote_name, remote_type, src_path),
            get_remote_connection_path(remote_name, remote_type, dest_path)
        ],
        remote_names = [remote_name],
        files_from = files_from,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Delete a remote path and everything under it with rclone purge
def purge_path_on_remote(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_transfer(
        subcommand = "purge",
        transfer_paths = [get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Delete single file on remote
def delete_file_on_remote(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_transfer(
        subcommand = "deletefile",
        transfer_paths = [get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        progress = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The recycle bin path under remote_path, or None, logging an error, when the recycle folder
# is empty or does not name a folder inside remote_path
def get_recycle_bin_path(remote_path, recycle_folder):
    folder = posixpath.normpath((recycle_folder or "").replace("\\", "/"))
    if folder in (".", "..") or folder.startswith(("/", "../")):
        logger.log_error("Recycle folder must name a folder inside %s, not '%s'" % (remote_path, recycle_folder))
        return None
    return os.path.join(remote_path, folder).replace("\\", "/")

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
    recycle_bin_path = get_recycle_bin_path(remote_path, recycle_folder)
    if not recycle_bin_path:
        return False

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
    recycle_bin_path = get_recycle_bin_path(remote_path, recycle_folder)
    if not recycle_bin_path:
        return False

    # Purge recycle bin
    return purge_path_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = recycle_bin_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Make the local path match the remote with rclone sync, deleting local extras
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
    return run_transfer(
        subcommand = "sync",
        transfer_paths = [get_remote_connection_path(remote_name, remote_type, remote_path), local_path],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PULL,
        excludes = excludes,
        interactive = interactive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Make the remote match the local path with rclone sync, deleting remote extras
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
    return run_transfer(
        subcommand = "sync",
        transfer_paths = [local_path, get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.PUSH,
        excludes = excludes,
        interactive = interactive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Two-way rclone bisync between local and remote, requiring check-access files; resync rebuilds its state
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
    return run_transfer(
        subcommand = "bisync",
        transfer_paths = [local_path, get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.MERGE,
        excludes = excludes,
        extra_flags = ["--check-access"] + (["--resync"] if resync else []),
        interactive = interactive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Copy a file from one remote to another; verbose runs show rclone progress unless show_progress is off
def copy_remote_to_remote(
    src_remote_name,
    src_remote_type,
    src_remote_path,
    dest_remote_name,
    dest_remote_type,
    dest_remote_path,
    show_progress = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    return run_transfer(
        subcommand = "copyto",
        transfer_paths = [
            get_remote_connection_path(src_remote_name, src_remote_type, src_remote_path),
            get_remote_connection_path(dest_remote_name, dest_remote_type, dest_remote_path)
        ],
        remote_names = [src_remote_name, dest_remote_name],
        progress = show_progress,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
