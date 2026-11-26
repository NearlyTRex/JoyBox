# Downloads and uploads through rclone, and the hash sidecar databases that
# uploads keep current and hashed listings read from.

# Imports
import os
import os.path
import sqlite3
import concurrent.futures
import contextlib
import functools

# Local imports
from joybox import config
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import hashing
from joybox import sqlitedb
from joybox import sync

# Constants
HASH_DATABASE_FILE = ".locker_hashes.db"

# Directories past either size are hashed one at a time rather than in parallel
LARGE_DIRECTORY_FILE_COUNT = 500
LARGE_DIRECTORY_SIZE = 10 * 1024 * 1024 * 1024

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

    # A single file is copied onto its destination, without the directory flags
    remote_full = sync.get_remote_connection_path(remote_name, remote_type, remote_path)
    if not local_path.endswith("/") and not paths.is_path_directory(local_path):
        return sync.is_file_list_readable(files_from) and sync.run_transfer(
            subcommand = "copyto",
            transfer_paths = [remote_full, local_path],
            remote_names = [remote_name],
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return sync.run_transfer(
        subcommand = "copy",
        transfer_paths = [remote_full, local_path],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.DOWNLOAD,
        excludes = excludes,
        files_from = files_from,
        interactive = interactive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

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
    if not sync.run_transfer(
        subcommand = "copy",
        transfer_paths = [local_path, sync.get_remote_connection_path(remote_name, remote_type, remote_path)],
        remote_names = [remote_name],
        remote_type = remote_type,
        remote_action_type = config.RemoteActionType.UPLOAD,
        excludes = excludes,
        files_from = files_from,
        extra_flags = ["--ignore-existing"] if skip_existing else [],
        interactive = interactive,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure):
        return False

    # Upload hash sidecars to local root if specified
    if local_root is not None and update_sidecar:
        update_uploaded_sidecar(remote_name, remote_type, remote_path, local_path, local_root, verbose, pretend_run)
    return True

# Add files just uploaded to the hash sidecar under their local root. The upload itself
# succeeded, so a sidecar that cannot be updated is only warned about.
def update_uploaded_sidecar(remote_name, remote_type, remote_path, local_path, local_root, verbose, pretend_run):
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

# A temporary directory for working on a hash database, yielding the database's path in it,
# or None when the directory cannot be made; the directory is removed afterwards
@contextlib.contextmanager
def temporary_hash_database(verbose = False):
    with fileops.temporary_directory(verbose = verbose) as temp_dir:
        if not temp_dir:
            logger.log_error("Failed to create temp directory for hash database")
            yield None
            return
        yield paths.join_paths(temp_dir, HASH_DATABASE_FILE)

# An open hash database, closed afterwards. Its tables are created first when initializing.
@contextlib.contextmanager
def opened_hash_database(db_path, initialize = False):
    hash_db = sqlitedb.HashDatabase(db_path)
    try:
        hash_db.open()
        if initialize:
            hash_db.initialize()
        yield hash_db
    finally:
        hash_db.close()

# Read a downloaded hash database into a hash listing, or None when it cannot be read
def read_hash_database(db_path, remote_db_path):
    try:
        with opened_hash_database(db_path) as hash_db:
            entries = hash_db.get_all_hashes()
    except sqlite3.Error as e:
        logger.log_error("Unreadable hash database from %s: %s" % (remote_db_path, e))
        return None
    return {
        entry["file_path"]: sync.get_hash_entry(entry["file_path"], entry.get("hash"), entry.get("size"), entry.get("mtime"))
        for entry in entries if entry.get("file_path")
    }

# List files with hashes from hash database
def list_files_with_hashes_from_sidecar(
    remote_name,
    remote_type,
    remote_path,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    with temporary_hash_database() as temp_db_path:
        if not temp_db_path:
            return None

        # A remote without a sidecar has no hashes, which is not a failure
        remote_db_path = get_hash_database_path(remote_path)
        if not sync.does_file_exist(remote_name, remote_type, remote_db_path, verbose = verbose):
            if verbose:
                logger.log_info("No hash database found")
            return {}

        # Download the database. This is a read into a temporary directory, so it runs even
        # on a pretend run - otherwise a dry run would see no sidecar and an empty remote.
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
        hash_map = read_hash_database(temp_db_path, remote_db_path)
    if verbose and hash_map is not None:
        logger.log_info("Loaded %d file hashes from database" % len(hash_map))
    return hash_map

# Get hash database path
def get_hash_database_path(remote_path = ""):
    return paths.join_paths(remote_path, HASH_DATABASE_FILE).replace("\\", "/")

# Get the hash data a sidecar keeps for a file, or None when it cannot be hashed
def get_file_hash_data(file_path, pretend_run = False):
    file_hash = hashing.calculate_file_md5(src = file_path, verbose = False, pretend_run = pretend_run)
    if not file_hash:
        return None
    return {
        "hash": file_hash,
        "size": paths.get_file_size(file_path),
        "mtime": paths.get_file_mod_time(file_path)
    }

# Build hash data for a file, or for the files in a directory
def build_hash_sidecar_data(local_path, file_list = None, parallel_files = 4, pretend_run = False, verbose = False):

    # A single file
    if paths.is_path_file(local_path):
        file_data = get_file_hash_data(local_path, pretend_run = pretend_run)
        return {paths.get_filename_file(local_path): file_data} if file_data else {}
    if not paths.is_path_directory(local_path):
        return {}

    # Every file below the directory unless a list is given
    if file_list is None:
        file_list = paths.build_file_list(local_path, use_relative_paths = True)
    total_files = len(file_list)
    if verbose and total_files > 0:
        logger.log_info("  Hashing %d files..." % total_files)

    # Hash files in parallel
    def hash_file(rel_file):
        full_file = paths.join_paths(local_path, rel_file)
        return get_file_hash_data(full_file, pretend_run = pretend_run) if paths.is_path_file(full_file) else None
    hash_data = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_files) as executor:
        futures = {executor.submit(hash_file, rel_file): rel_file for rel_file in file_list}
        for completed, future in enumerate(concurrent.futures.as_completed(futures), start = 1):
            if verbose and total_files > 100 and completed % 100 == 0:
                logger.log_info("  Hashed %d/%d files..." % (completed, total_files))
            if future.result():
                hash_data[futures[future]] = future.result()
    return hash_data

# Get the hash unit for a directory: its direct files, their count and total size, or None without any
def get_directory_hash_unit(current_dir, filenames):
    files = sorted(filename for filename in filenames if paths.is_path_file(os.path.join(current_dir, filename)))
    if not files:
        return None
    return {
        "path": current_dir,
        "files": files,
        "file_count": len(files),
        "total_size": sum(paths.get_file_size(os.path.join(current_dir, filename)) for filename in files)
    }

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
        dir_info = get_directory_hash_unit(current_dir, filenames)
        if not dir_info:
            continue

        # Separate large directories
        is_large = (
            (large_file_count is not None and dir_info["file_count"] > large_file_count) or
            (large_total_size is not None and dir_info["total_size"] > large_total_size))
        if is_large:
            large_dirs.append(dir_info)
        else:
            small_dirs.append(dir_info)
    return small_dirs, large_dirs

# Get a remote path relative to a remote root, or None when it is outside it
def get_remote_relative_path(remote_path, remote_root):
    root = remote_root.rstrip("/")
    if remote_path in (root, remote_root):
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

# Download the existing hash database before adding to it. Carrying on without it would
# upload a database holding only the new files over the full one.
def fetch_existing_hash_database(remote_name, remote_type, remote_db_path, temp_db_path, verbose, pretend_run, exit_on_failure):
    if not sync.does_file_exist(remote_name, remote_type, remote_db_path, verbose = verbose):
        logger.log_info("No existing hash database found, creating new one...")
        return True
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
    return True

# Get the paths a hash database already holds
def read_hash_database_paths(db_path):
    with opened_hash_database(db_path, initialize = True) as hash_db:
        return {entry["file_path"] for entry in hash_db.get_all_hashes()}

# Get the units a sidecar upload hashes, as (local path, remote path, files) tuples for the
# small directories and for the large ones; a single file is one small unit
def get_hash_sidecar_units(local_path, remote_path, excludes):
    if paths.is_path_file(local_path):
        return [(local_path, remote_path, None)], []
    if not paths.is_path_directory(local_path):
        return [], []
    small_dirs, large_dirs = build_hash_sidecar_directory_list(
        local_path = local_path,
        excludes = excludes,
        large_file_count = LARGE_DIRECTORY_FILE_COUNT,
        large_total_size = LARGE_DIRECTORY_SIZE)
    def to_unit(dir_info):
        dir_rel = os.path.relpath(dir_info["path"], local_path)
        if dir_rel == os.curdir:
            return (dir_info["path"], remote_path, dir_info["files"])
        return (dir_info["path"], paths.join_paths(remote_path, dir_rel).replace("\\", "/"), dir_info["files"])
    return [to_unit(dir_info) for dir_info in small_dirs], [to_unit(dir_info) for dir_info in large_dirs]

# Hash one unit of a sidecar upload, returning whether every file hashed and the database
# entries for the files the database does not already hold
def hash_sidecar_unit(unit, local_root, existing_paths, parallel_files, pretend_run, verbose):
    current_local, current_remote, current_files = unit
    logger.log_info("Processing: %s" % paths.get_filename_file(current_local))
    hash_data = build_hash_sidecar_data(
        local_path = current_local,
        file_list = current_files,
        parallel_files = parallel_files,
        pretend_run = pretend_run,
        verbose = verbose)

    # Key entries by their path relative to the sidecar root
    dir_rel = get_remote_relative_path(current_remote, local_root)
    if dir_rel is None:
        dir_rel = current_remote.lstrip("/")
    entries = []
    for rel_file, file_info in hash_data.items():
        file_path = paths.join_paths(dir_rel, rel_file).replace("\\", "/")
        if file_path not in existing_paths:
            entries.append(dict(file_info, file_path = file_path))

    # A file that could not be hashed is missing from the sidecar
    expected_count = 1 if current_files is None else len(current_files)
    if not pretend_run and len(hash_data) < expected_count:
        logger.log_error("Failed to hash %d files in %s" % (expected_count - len(hash_data), current_local))
        return False, entries
    return True, entries

# Hash sidecar units, the large ones one at a time first and the rest in parallel, yielding
# each one's result; closing it early cancels the units not yet started
def hash_sidecar_units(large_units, small_units, hash_unit, parallel_dirs):
    if large_units:
        logger.log_info("Processing %d large directories sequentially..." % len(large_units))
    for unit in large_units:
        yield hash_unit(unit)
    if not small_units:
        return
    logger.log_info("Processing %d directories in parallel..." % len(small_units))
    with concurrent.futures.ThreadPoolExecutor(max_workers = parallel_dirs) as executor:
        futures = [executor.submit(hash_unit, unit) for unit in small_units]
        try:
            for future in concurrent.futures.as_completed(futures):
                yield future.result()
        finally:
            executor.shutdown(wait = False, cancel_futures = True)

# Gather the results of hashing sidecar units: whether all hashed and their entries, or
# None when a failure stops the run
def collect_sidecar_entries(results, exit_on_failure):
    all_success, all_entries = True, []
    with contextlib.closing(results):
        for success, entries in results:
            all_entries += entries
            all_success = all_success and success
            if not success and exit_on_failure:
                return None
    return all_success, all_entries

# Add hash entries to the database file and upload it back to its remote directory
def store_hash_database(remote_name, remote_type, remote_db_path, temp_db_path, entries, verbose, pretend_run, exit_on_failure):
    with opened_hash_database(temp_db_path, initialize = True) as hash_db:
        if entries and not pretend_run:
            logger.log_info("Inserting %d hash entries into database..." % len(entries))
            hash_db.set_hashes(entries)
    logger.log_info("Uploading hash database to remote...")
    return upload_files_to_remote(
        remote_name = remote_name,
        remote_type = remote_type,
        remote_path = paths.get_filename_directory(remote_db_path),
        local_path = temp_db_path,
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
    remote_db_path = get_hash_database_path(local_root)
    with temporary_hash_database(verbose = verbose) as temp_db_path:
        if not temp_db_path or not fetch_existing_hash_database(
            remote_name, remote_type, remote_db_path, temp_db_path, verbose, pretend_run, exit_on_failure):
            return False
        existing_paths = read_hash_database_paths(temp_db_path) if skip_existing else set()

        # Hash every unit, nothing to do without any
        small_units, large_units = get_hash_sidecar_units(local_path, remote_path, excludes or [])
        if not small_units and not large_units:
            return True
        hash_unit = functools.partial(
            hash_sidecar_unit,
            local_root = local_root,
            existing_paths = existing_paths,
            parallel_files = parallel_files,
            pretend_run = pretend_run,
            verbose = verbose)
        result = collect_sidecar_entries(hash_sidecar_units(large_units, small_units, hash_unit, parallel_dirs), exit_on_failure)
        if result is None:
            return False
        uploaded = store_hash_database(
            remote_name, remote_type, remote_db_path, temp_db_path, result[1], verbose, pretend_run, exit_on_failure)
        return result[0] and uploaded
