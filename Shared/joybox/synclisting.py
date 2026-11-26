# Listing remote files, with or without their hashes, and mounting remotes.

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import rcloneremotes
from joybox import serialization
from joybox import strings
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import platform_info
from joybox import sync

# The names rclone lists each hash type under
LISTED_HASH_NAMES = {
    config.HashType.MD5: ("MD5", "md5"),
    config.HashType.SHA1: ("SHA-1", "sha1"),
    config.HashType.SHA256: ("SHA-256", "sha256")
}

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

    # lsd lists directories and ls files, files one level deep unless recursive
    if only_directories:
        subcommand = ["lsd", "-R"] if recursive else ["lsd"]
    else:
        subcommand = ["ls"] if recursive else ["ls", "--max-depth", 1]
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return False
    return sync.run_rclone_command(
        cmd = [rclone_tool] + subcommand + [sync.get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Make the mount point on unix, where rclone mounts onto an existing directory, returning
# False when there is no empty directory there to mount onto
def prepare_mount_point(mount_path, verbose = False, pretend_run = False, exit_on_failure = False):
    if not platform_info.is_unix_platform():
        return True
    fileops.make_directory(
        src = mount_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not pretend_run and (not paths.does_path_exist(mount_path) or not paths.is_directory_empty(mount_path)):
        logger.log_error("Mount point %s needs to exist and be empty" % mount_path)
        return False
    return True

# Get the flags a mount runs with after its paths: as a daemon on unix, the asked for
# checks left off, and logging to a file when verbose
def get_mount_flags(no_checksum = False, no_modtime = False, no_seek = False, read_only = False, verbose = False):
    flags = ["--daemon"] if platform_info.is_unix_platform() else []
    for enabled, flag in [
        (no_checksum, "--no-checksum"),
        (no_modtime, "--no-modtime"),
        (no_seek, "--no-seek"),
        (read_only, "--read-only")]:
        if enabled:
            flags.append(flag)
    if verbose:
        flags += ["--log-file", "/tmp/rclone.log", "--log-level", "INFO"]
    return flags

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
    if not prepare_mount_point(mount_path, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure):
        return False
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return False

    # Run mount, which stays running as a daemon on unix
    mount_cmd = [rclone_tool, "mount", "--vfs-cache-mode", "off" if no_cache else "full"]
    mount_cmd += [sync.get_remote_connection_path(remote_name, remote_type, remote_path), mount_path]
    mount_cmd += get_mount_flags(no_checksum, no_modtime, no_seek, read_only, verbose)
    return sync.run_rclone_command(
        cmd = mount_cmd,
        remote_names = [remote_name],
        options = commandbase.create_command_options(is_daemon = platform_info.is_unix_platform()),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Get a listed file's hash of a type, under either of the names rclone gives it
def get_listed_hash(hashes, hash_type):
    if not isinstance(hashes, dict):
        return ""
    for name in LISTED_HASH_NAMES.get(hash_type, ()):
        if name in hashes:
            return hashes[name]
    return ""

# Parse rclone's JSON file listing, or None when it is not a list. rclone prints [] for an
# empty remote, so empty output is a failure too.
def parse_file_listing(output):
    text = output.decode() if isinstance(output, bytes) else output
    if not text or not text.strip():
        return None
    files_list = serialization.parse_json_string(text)
    return files_list if isinstance(files_list, list) else None

# Build a hash listing from rclone's file listing, skipping directories and unnamed entries
def build_listed_hash_map(files_list, hash_type):
    hash_map = {}
    for file_info in files_list:
        if not isinstance(file_info, dict) or file_info.get("IsDir", False):
            continue
        rel_path = file_info.get("Path")
        if rel_path and isinstance(rel_path, str):
            hash_map[rel_path] = sync.get_hash_entry(
                rel_path,
                get_listed_hash(file_info.get("Hashes"), hash_type),
                file_info.get("Size"),
                strings.parse_timestamp(file_info.get("ModTime") or ""))
    return hash_map

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
    rclone_tool = programs.find_tool_program("RClone")
    if not rclone_tool:
        return None
    if verbose:
        logger.log_info("Listing files with hashes from remote: %s" % remote_name)

    # Capture the JSON on stdout while logging rclone's stats from stderr, so a long listing
    # shows it is alive. --fast-list lists recursively in one call where the backend can.
    # Listing only reads, so it runs on a pretend run too, which would otherwise see nothing.
    lsjson_output, lsjson_code = command.run_command(
        cmd = [rclone_tool, "lsjson", "--recursive", "--fast-list", "--hash", "--files-only", "-v", "--stats", "5s",
            sync.get_remote_connection_path(remote_name, remote_type, remote_path)] + sync.get_exclude_flags(excludes or []),
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
    files_list = parse_file_listing(lsjson_output)
    if files_list is None:
        logger.log_error("Unreadable file listing from remote: %s" % remote_name)
        return None
    hash_map = build_listed_hash_map(files_list, hash_type or config.HashType.MD5)
    if verbose:
        logger.log_info("Loaded %d file hashes" % len(hash_map))
    return hash_map
