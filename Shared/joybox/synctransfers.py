# Downloads and uploads through rclone, and the hash sidecar databases that
# uploads keep current and hashed listings read from.

# Imports
import os
import os.path
import sqlite3
import threading
import concurrent.futures

# Local imports
from joybox import config
from joybox import command
from joybox import programs
from joybox import rcloneremotes
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import hashing
from joybox import sqlitedb
from joybox import sync

# Constants
HASH_DATABASE_FILE = ".locker_hashes.db"

# Download files from remote
def download_files_from_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    excludes = None,
    files_from = None,
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

    # A file list that cannot be read must not widen the transfer to everything
    if files_from and not paths.is_path_file(files_from):
        logger.log_error("File list %s does not exist" % files_from)
        return False

    # Get copy command
    is_directory_dest = local_path.endswith("/") or paths.is_path_directory(local_path)
    copy_cmd = [
        rclone_tool,
        "copy" if is_directory_dest else "copyto",
        sync.get_remote_connection_path(remote_name, remote_type, remote_path),
        local_path
    ]
    if is_directory_dest:
        copy_cmd += sync.get_common_remote_flags(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_action_type = config.RemoteActionType.DOWNLOAD)
        copy_cmd += sync.get_exclude_flags(excludes)
        if files_from:
            copy_cmd += ["--files-from", files_from]
        if interactive:
            copy_cmd += ["--interactive"]
    if pretend_run:
        copy_cmd += ["--dry-run"]
    if verbose:
        copy_cmd += [
            "--verbose",
            "--progress"
        ]

    # Run copy command
    code = command.run_returncode_command(
        cmd = copy_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Upload files to remote
def upload_files_to_remote(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    local_root = None,
    excludes = None,
    files_from = None,
    skip_existing = False,
    interactive = False,
    update_sidecar = True,
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

    # Get copy command
    copy_cmd = [
        rclone_tool,
        "copy",
        local_path,
        sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    ]
    copy_cmd += sync.get_common_remote_flags(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD)
    copy_cmd += sync.get_exclude_flags(excludes)
    if files_from:
        copy_cmd += ["--files-from", files_from]
    if skip_existing:
        copy_cmd += ["--ignore-existing"]
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
    code = command.run_returncode_command(
        cmd = copy_cmd,
        options = rcloneremotes.get_rclone_options([remote_name]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Upload hash sidecars to local root if specified
    if local_root is not None and update_sidecar:
        if not upload_hash_sidecar_files(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_path,
            local_path = local_path,
            local_root = local_root,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False):
            logger.log_warning("Uploaded %s but could not update its hash sidecar" % local_path)
    return True

# List files with hashes from hash database
def list_files_with_hashes_from_sidecar(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temp directory for database download
    success, temp_dir = fileops.create_temporary_directory()
    if not success:
        logger.log_error("Failed to create temp directory")
        return None

    # Build hash map
    hash_map = {}
    hash_db = None
    try:
        # Build paths
        remote_db_path = get_hash_database_path(remote_path)
        temp_db_path = paths.join_paths(temp_dir, HASH_DATABASE_FILE)

        # A remote without a sidecar has no hashes, which is not a failure
        if not sync.does_file_exist(remote_name, remote_type, remote_db_path, verbose = verbose):
            if verbose:
                logger.log_info("No hash database found")
            return {}

        # Download database from remote. This is a read into a temp dir (cleaned up
        # below), so run it even under pretend_run - otherwise a dry run would see no
        # sidecar and report the whole remote as empty.
        if verbose:
            logger.log_info("Downloading hash database from: %s" % remote_db_path)
        downloaded = download_files_from_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = remote_db_path,
            local_path = temp_db_path,
            verbose = verbose,
            pretend_run = False,
            exit_on_failure = exit_on_failure)
        if not downloaded or not paths.is_path_file(temp_db_path):
            logger.log_error("Failed to download hash database from: %s" % remote_db_path)
            return None

        # Open database and read all hashes
        try:
            hash_db = sqlitedb.HashDatabase(temp_db_path)
            hash_db.open()
            entries = hash_db.get_all_hashes()
        except sqlite3.Error as e:
            logger.log_error("Unreadable hash database from %s: %s" % (remote_db_path, e))
            return None
        for entry in entries:
            file_path = entry.get("file_path")
            if not file_path:
                continue
            hash_map[file_path] = {
                "filename": paths.get_filename_file(file_path),
                "dir": paths.get_filename_directory(file_path),
                "hash": entry.get("hash") or "",
                "size": entry.get("size") or 0,
                "mtime": entry.get("mtime") or 0
            }

    finally:

        # Close database and clean up temp dir
        if hash_db:
            hash_db.close()
        fileops.remove_directory(temp_dir, exit_on_failure = False)

    # All done
    if verbose:
        logger.log_info("Loaded %d file hashes from database" % len(hash_map))
    return hash_map

# Get hash database path
def get_hash_database_path(remote_path = ""):
    return paths.join_paths(remote_path, HASH_DATABASE_FILE).replace("\\", "/")

# Build hash data for a file, or for the files in a directory
def build_hash_sidecar_data(local_path, file_list = None, parallel_files = 4, pretend_run = False, verbose = False):
    hash_data = {}

    # Process files to add
    if paths.is_path_file(local_path):

        # Single file
        filename = paths.get_filename_file(local_path)
        file_hash = hashing.calculate_file_md5(src = local_path, verbose = False, pretend_run = pretend_run)
        if file_hash:
            hash_data[filename] = {
                "hash": file_hash,
                "size": paths.get_file_size(local_path),
                "mtime": paths.get_file_mod_time(local_path)
            }
    elif paths.is_path_directory(local_path):

        # Build file list, every file below the directory unless one is given
        if file_list is None:
            file_list = paths.build_file_list(local_path, use_relative_paths = True)
        total_files = len(file_list)
        if verbose and total_files > 0:
            logger.log_info("  Hashing %d files..." % total_files)

        # Hash files in parallel using thread pool
        completed = [0]
        def hash_file(rel_file):
            full_file = paths.join_paths(local_path, rel_file)
            if not paths.is_path_file(full_file):
                return None
            file_hash = hashing.calculate_file_md5(src = full_file, verbose = False, pretend_run = pretend_run)
            if file_hash:
                return (rel_file, {
                    "hash": file_hash,
                    "size": paths.get_file_size(full_file),
                    "mtime": paths.get_file_mod_time(full_file)
                })
            return None

        # Hash files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_files) as executor:
            futures = {executor.submit(hash_file, rel_file): rel_file for rel_file in file_list}
            for future in concurrent.futures.as_completed(futures):
                completed[0] += 1
                if verbose and total_files > 100 and completed[0] % 100 == 0:
                    logger.log_info("  Hashed %d/%d files..." % (completed[0], total_files))
                result = future.result()
                if result:
                    hash_data[result[0]] = result[1]
    return hash_data

# Build the units a sidecar is hashed in: every directory holding files, with its direct files
def build_hash_sidecar_directory_list(
    local_path,
    excludes = (),
    large_file_count = None,
    large_total_size = None):

    # Collect directories, skipping hidden and excluded ones
    small_dirs = []
    large_dirs = []
    for current_dir, dirnames, filenames in os.walk(local_path):
        rel_dir = os.path.relpath(current_dir, local_path)
        if rel_dir == os.curdir:
            rel_dir = ""
        dirnames[:] = sorted(
            dirname for dirname in dirnames
            if not dirname.startswith(".") and
            not paths.matches_exclude_pattern(os.path.join(rel_dir, dirname), excludes or []))

        # Gather direct files
        files = sorted(
            filename for filename in filenames
            if paths.is_path_file(os.path.join(current_dir, filename)))
        if not files:
            continue
        total_size = sum(paths.get_file_size(os.path.join(current_dir, filename)) for filename in files)
        dir_info = {
            "path": current_dir,
            "files": files,
            "file_count": len(files),
            "total_size": total_size
        }

        # Separate large directories
        is_large = (
            (large_file_count is not None and len(files) > large_file_count) or
            (large_total_size is not None and total_size > large_total_size))
        if is_large:
            large_dirs.append(dir_info)
        else:
            small_dirs.append(dir_info)
    return small_dirs, large_dirs

# Get a remote path relative to a remote root, or None when it is outside it
def get_remote_relative_path(remote_path, remote_root):
    root = remote_root.rstrip("/")
    if remote_path == root or remote_path == remote_root:
        return ""
    if remote_path.startswith(root + "/"):
        return remote_path[len(root) + 1:]
    return None

# Clear hash sidecar files
def clear_hash_sidecar_files(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Delete the hash database file
    db_path = get_hash_database_path(remote_path)
    return sync.delete_file_on_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = db_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Upload hash sidecar files
def upload_hash_sidecar_files(
    remote_name,
    remote_type,
    remote_path,
    local_path,
    local_root,
    excludes = None,
    skip_existing = False,
    parallel_dirs = 4,
    parallel_files = 4,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get excludes
    excludes = [] if excludes is None else excludes

    # Create temp directory for database work
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(verbose = verbose)
    if not tmp_dir_success:
        logger.log_error("Failed to create temp directory for hash database")
        return False

    # Hash files
    hash_db = None
    try:
        # Build paths
        remote_db_path = get_hash_database_path(local_root)
        temp_db_path = paths.join_paths(tmp_dir_result, HASH_DATABASE_FILE)

        # Download existing database from remote if it exists. Carrying on without it
        # would upload a database holding only these files over the full one.
        if sync.does_file_exist(remote_name, remote_type, remote_db_path, verbose = verbose):
            logger.log_info("Downloading hash database from remote...")
            downloaded = download_files_from_remote(
                remote_name = remote_name,
                remote_type = remote_type,
                remote_path = remote_db_path,
                local_path = temp_db_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not downloaded or (not pretend_run and not paths.is_path_file(temp_db_path)):
                logger.log_error("Failed to download existing hash database")
                return False
        else:
            logger.log_info("No existing hash database found, creating new one...")

        # Open database
        hash_db = sqlitedb.HashDatabase(temp_db_path)
        hash_db.open()
        hash_db.initialize()

        # Get existing file paths for skip_existing check
        existing_paths = set()
        if skip_existing:
            for entry in hash_db.get_all_hashes():
                existing_paths.add(entry["file_path"])

        # Collect (local path, remote path, files) units, separated by size
        large_file_count_threshold = 500
        large_size_threshold = 10 * 1024 * 1024 * 1024  # 10 GB
        leaf_dirs = []
        large_dirs = []
        if paths.is_path_file(local_path):
            leaf_dirs = [(local_path, remote_path, None)]
        elif paths.is_path_directory(local_path):
            small_dir_infos, large_dir_infos = build_hash_sidecar_directory_list(
                local_path = local_path,
                excludes = excludes,
                large_file_count = large_file_count_threshold,
                large_total_size = large_size_threshold)

            # Convert to (local_path, remote_path, files) tuples
            def to_local_remote_tuple(dir_info):
                dir_rel = os.path.relpath(dir_info["path"], local_path)
                if dir_rel == os.curdir:
                    dir_remote = remote_path
                else:
                    dir_remote = paths.join_paths(remote_path, dir_rel).replace("\\", "/")
                return (dir_info["path"], dir_remote, dir_info["files"])
            leaf_dirs = [to_local_remote_tuple(d) for d in small_dir_infos]
            large_dirs = [to_local_remote_tuple(d) for d in large_dir_infos]

        # Nothing to hash
        if not leaf_dirs and not large_dirs:
            return True

        # Thread-safe list for collecting hash entries
        all_hash_entries = []
        entries_lock = threading.Lock()

        # Directory thread worker
        def process_dir_locally(dir_info):
            current_local, current_remote, current_files = dir_info
            dir_name = paths.get_filename_file(current_local)
            logger.log_info("Processing: %s" % dir_name)

            # Build hash data from local files
            hash_data = build_hash_sidecar_data(
                local_path = current_local,
                file_list = current_files,
                parallel_files = parallel_files,
                pretend_run = pretend_run,
                verbose = verbose)

            # Build the path of this unit relative to the sidecar root
            dir_rel = get_remote_relative_path(current_remote, local_root)
            if dir_rel is None:
                dir_rel = current_remote.lstrip("/")

            # Convert to database entries
            entries = []
            for rel_file, file_info in hash_data.items():
                file_path = paths.join_paths(dir_rel, rel_file).replace("\\", "/")

                # Skip if already exists and skip_existing is True
                if skip_existing and file_path in existing_paths:
                    continue

                # Add entry
                entries.append({
                    "file_path": file_path,
                    "hash": file_info.get("hash"),
                    "size": file_info.get("size"),
                    "mtime": file_info.get("mtime")
                })

            # Add to collection
            if entries:
                with entries_lock:
                    all_hash_entries.extend(entries)

            # A file that could not be hashed is missing from the sidecar
            expected_count = 1 if current_files is None else len(current_files)
            if not pretend_run and len(hash_data) < expected_count:
                logger.log_error("Failed to hash %d files in %s" % (expected_count - len(hash_data), current_local))
                return False
            return True

        # Process large directories sequentially first
        all_success = True
        if large_dirs:
            logger.log_info("Processing %d large directories sequentially..." % len(large_dirs))
            for dir_info in large_dirs:
                if not process_dir_locally(dir_info):
                    all_success = False
                    if exit_on_failure:
                        return False

        # Process smaller directories in parallel
        if leaf_dirs:
            logger.log_info("Processing %d directories in parallel..." % len(leaf_dirs))
            with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_dirs) as executor:
                futures = {executor.submit(process_dir_locally, dir_info): dir_info for dir_info in leaf_dirs}
                for future in concurrent.futures.as_completed(futures):
                    if not future.result():
                        all_success = False
                        if exit_on_failure:
                            executor.shutdown(wait = False, cancel_futures = True)
                            return False

        # Batch insert all hash entries
        if all_hash_entries and not pretend_run:
            logger.log_info("Inserting %d hash entries into database..." % len(all_hash_entries))
            hash_db.set_hashes(all_hash_entries)

        # Close database before uploading it
        hash_db.close()
        hash_db = None

        # Upload database back to remote
        logger.log_info("Uploading hash database to remote...")
        upload_success = upload_files_to_remote(
            remote_name = remote_name,
            remote_type = remote_type,
            remote_path = paths.get_filename_directory(remote_db_path),
            local_path = temp_db_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return all_success and upload_success

    finally:

        # Close database and clean up the temp directory, which exists even on a pretend run
        if hash_db:
            hash_db.close()
        fileops.remove_directory(
            src = tmp_dir_result,
            verbose = verbose,
            exit_on_failure = False)
