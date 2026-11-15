# Listing remote files, with or without their hashes, and mounting remotes.

# Imports

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import rcloneremotes
from joybox import serialization
from joybox import strings
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import platform_info
from joybox import sync

# List files
def list_files(
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
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
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
        sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Run list command
    code = command.run_returncode_command(
        cmd = list_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Mount files
def mount_files(
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

    # Ignore already mounted
    if paths.does_path_exist(mount_path) and not paths.is_directory_empty(mount_path):
        return True

    # Create mount point
    if platform_info.is_unix_platform():
        fileops.make_directory(
            src = mount_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not pretend_run and (not paths.does_path_exist(mount_path) or not paths.is_directory_empty(mount_path)):
            logger.log_error("Mount point %s needs to exist and be empty" % mount_path)
            return False

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
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
        sync.get_remote_connection_path(remote_name, remote_type, remote_path),
        mount_path
    ]
    if platform_info.is_unix_platform():
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
        mount_cmd += [
            "--log-file", "/tmp/rclone.log",
            "--log-level", "INFO"
        ]

    # Run mount command
    code = command.run_returncode_command(
        cmd = mount_cmd,
        options = rcloneremotes.get_rclone_options([remote_name], command.create_command_options(
            is_daemon = platform_info.is_unix_platform())),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# List files with hashes
def list_files_with_hashes(
    remote_name,
    remote_type,
    remote_path,
    hash_type = None,
    excludes = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get excludes
    excludes = [] if excludes is None else excludes

    # Use default hash type
    if hash_type is None:
        hash_type = config.HashType.MD5

    # Get tool
    rclone_tool = None
    if programs.is_tool_installed("RClone"):
        rclone_tool = programs.get_tool_program("RClone")
    if not rclone_tool:
        logger.log_error("RClone was not found")
        return None

    # Build lsjson command. --fast-list uses a single recursive listing where the backend
    # supports it (e.g. Google Drive), instead of one API call per directory - a large
    # speedup for deep trees (and ignored by backends that don't support it).
    lsjson_cmd = [
        rclone_tool,
        "lsjson",
        "--recursive",
        "--fast-list",
        "--hash",
        "--files-only",
        "-v",
        "--stats", "5s",
        sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    ]

    # Add exclude flags
    lsjson_cmd += sync.get_exclude_flags(excludes)
    if verbose:
        logger.log_info("Listing files with hashes from remote: %s" % remote_name)

    # Run lsjson command. Capture the JSON on stdout while streaming rclone's progress
    # (stats heartbeat) from stderr to the logger, so a long listing shows it is alive.
    # Listing is read-only, so it runs for real on a pretend run too; otherwise a dry
    # run would see an empty remote.
    lsjson_output, lsjson_code = command.run_command(
        cmd = lsjson_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        capture_output = True,
        log_stderr = True,
        verbose = verbose,
        pretend_run = False,
        exit_on_failure = exit_on_failure)

    # A failed listing may be partial, which would read as files missing from the remote
    if lsjson_code != 0:
        logger.log_error("Unable to list files with hashes from remote: %s" % remote_name)
        return None

    # Parse JSON output; rclone prints [] for an empty remote, so anything else is a failure
    lsjson_text = lsjson_output
    if isinstance(lsjson_output, bytes):
        lsjson_text = lsjson_output.decode()
    files_list = None
    if lsjson_text and lsjson_text.strip():
        files_list = serialization.parse_json_string(lsjson_text)
    if not isinstance(files_list, list):
        logger.log_error("Unreadable file listing from remote: %s" % remote_name)
        return None

    # Build map
    hash_map = {}
    for file_info in files_list:
        if not isinstance(file_info, dict) or file_info.get("IsDir", False):
            continue
        rel_path = file_info.get("Path")
        if not rel_path or not isinstance(rel_path, str):
            continue

        # Get hash from Hashes dict
        hashes = file_info.get("Hashes")
        if not isinstance(hashes, dict):
            hashes = {}
        file_hash = ""
        if hash_type == config.HashType.MD5:
            file_hash = hashes.get("MD5", hashes.get("md5", ""))
        elif hash_type == config.HashType.SHA1:
            file_hash = hashes.get("SHA-1", hashes.get("sha1", ""))
        elif hash_type == config.HashType.SHA256:
            file_hash = hashes.get("SHA-256", hashes.get("sha256", ""))

        # Parse modification time
        mtime = strings.parse_timestamp(file_info.get("ModTime") or "")

        # Add to map
        hash_map[rel_path] = {
            "filename": paths.get_filename_file(rel_path),
            "dir": paths.get_filename_directory(rel_path),
            "hash": file_hash or "",
            "size": file_info.get("Size") or 0,
            "mtime": mtime
        }

    # All done
    if verbose:
        logger.log_info("Loaded %d file hashes" % len(hash_map))
    return hash_map
