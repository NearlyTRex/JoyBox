# Imports
import fnmatch
import os
import os.path

# Local imports
from joybox import config
from joybox import environment
from joybox import fileops
from joybox import hashutil
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import cryption

###########################################################

# Total size and files of each directory listed in the JSON hash files, keyed by directory
def _aggregate_hash_sets(filenames):
    hash_sets = {}
    for hash_filename in sorted(filenames):
        hash_contents = read_hash_file_json(hash_filename)
        for hash_key in sorted(hash_contents.keys()):
            file_location = hash_key
            file_directory = paths.get_filename_directory(file_location)
            file_size = int(hash_contents[hash_key]["size"])
            if file_directory not in hash_sets:
                hash_sets[file_directory] = {}
                hash_sets[file_directory]["size"] = 0
                hash_sets[file_directory]["files"] = []
            hash_sets[file_directory]["size"] += file_size
            hash_sets[file_directory]["files"].append(file_location)
    return hash_sets

# Split the files listed in JSON hash files into numbered groups of at most max_group_size bytes, never splitting a directory
def get_file_groupings(filenames, max_group_size):

    # Group results
    results = {}

    # Add empty group
    def add_empty_group(group_name):
        results[group_name] = {}
        results[group_name]["size"] = 0
        results[group_name]["files"] = []

    # Groups info
    group_counter = 1
    group_name = "Group" + str(group_counter)

    # Create initial group
    add_empty_group(group_name)

    # Aggregate similar files together into sets
    hash_sets = _aggregate_hash_sets(filenames)

    # Add to each group based on sizing
    for hash_set_key in sorted(hash_sets.keys()):
        hash_set_size = hash_sets[hash_set_key]["size"]
        hash_set_files = hash_sets[hash_set_key]["files"]

        # Check if we need to start a new group
        if results[group_name]["files"] and hash_set_size + results[group_name]["size"] > max_group_size:
            group_counter += 1
            group_name = "Group" + str(group_counter)
            add_empty_group(group_name)

        # Add to group
        results[group_name]["size"] += hash_set_size
        results[group_name]["files"] += hash_set_files

    # Return groups
    return results

###########################################################

# Entries of a JSON hash file keyed by dir/filename, with missing encryption fields filled; empty when the file is not a list
def read_hash_file_json(
    src,
    verbose = False,
    exit_on_failure = False):
    json_hashes = serialization.read_json_file(
        src = src,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    hash_contents = {}
    if isinstance(json_hashes, list):
        for json_hash in json_hashes:
            if "filename_enc" not in json_hash:
                json_hash["filename_enc"] = cryption.generate_encrypted_filename(json_hash["filename"])
            if "hash_enc" not in json_hash:
                json_hash["hash_enc"] = ""
            if "size_enc" not in json_hash:
                json_hash["size_enc"] = 0
            file_location = paths.join_paths(json_hash["dir"], json_hash["filename"])
            hash_contents[file_location] = json_hash
    return hash_contents

# Write hash entries as a JSON list sorted by key; returns whether the write succeeded
def write_hash_file_json(
    src,
    hash_contents,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    json_hashes = []
    for hash_key in sorted(hash_contents.keys()):
        json_hashes.append(hash_contents[hash_key])
    success = serialization.write_json_file(
        src = src,
        json_data = json_hashes,
        sort_keys = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

# The columns of a csv hash file, in order
HASH_FILE_COLUMNS = ["dir", "filename", "hash", "size", "mtime"]

# Entries of a CSV hash file keyed by dir/filename, size and mtime as ints; empty when the file is missing
def read_hash_file_csv(
    src,
    verbose = False,
    exit_on_failure = False):
    hash_contents = {}
    try:
        if verbose:
            logger.log_info("Reading CSV hash file: %s" % src)
        if not paths.does_path_exist(src):
            return hash_contents
        rows = serialization.read_csv_records(src, exit_on_failure = exit_on_failure)
        for row in rows or []:
            file_location = paths.join_paths(row["dir"], row["filename"])
            hash_contents[file_location] = {
                "dir": row["dir"],
                "filename": row["filename"],
                "hash": row["hash"],
                "size": int(row["size"]),
                "mtime": int(row["mtime"])
            }
    except (KeyError, ValueError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read CSV hash file: %s" % src)
            logger.log_error(e, quit_program = True)
    return hash_contents

# Write hash entries as CSV in the fixed column order, creating the folder; True without writing on a pretend run
def write_hash_file_csv(
    src,
    hash_contents,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if verbose:
        logger.log_info("Writing CSV hash file: %s" % src)
    if pretend_run:
        return True
    fileops.make_directory(
        src = paths.get_filename_directory(src),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    records = [{column: hash_contents[hash_key][column] for column in HASH_FILE_COLUMNS}
               for hash_key in sorted(hash_contents.keys())]
    return serialization.write_csv_records(src, HASH_FILE_COLUMNS, records, exit_on_failure = exit_on_failure)

# Rewrite a JSON hash file with its entries in key order
def sort_hash_file(
    src,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if verbose:
        logger.log_info("Sorting hash file %s" % src)
    hash_contents = read_hash_file_json(
        src = src,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return write_hash_file_json(
        src = src,
        hash_contents = hash_contents,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Hash entry fields that default to an empty string, and those held as ints
HASH_ENTRY_STRING_FIELDS = ["dir", "filename", "filename_enc", "hash", "hash_enc"]
HASH_ENTRY_INT_FIELDS = ["size", "size_enc", "mtime"]

# A hash entry's int field as an int: a string is parsed, falling back to 0, and anything else is kept
def _coerce_hash_entry_int(value):
    if not isinstance(value, str):
        return value
    try:
        return int(value)
    except ValueError:
        return 0

# Normalize hash entry to ensure all fields exist with correct types
def normalize_hash_entry(data):
    normalized = dict(data)
    for field in HASH_ENTRY_STRING_FIELDS:
        normalized.setdefault(field, "")
    for field in HASH_ENTRY_INT_FIELDS:
        normalized[field] = _coerce_hash_entry_int(normalized.get(field, 0))
    return normalized

# Normalize all entries in a hash contents dictionary
def normalize_hash_contents(hash_contents):
    normalized = {}
    for key, data in hash_contents.items():
        normalized[key] = normalize_hash_entry(data)
    return normalized

# Convert simple hash data to full format (add enc fields)
def convert_to_full_hash_entry(hash_data):
    full_data = dict(hash_data)
    if "filename_enc" not in full_data:
        full_data["filename_enc"] = ""
    if "hash_enc" not in full_data:
        full_data["hash_enc"] = ""
    if "size_enc" not in full_data:
        full_data["size_enc"] = 0
    return full_data

# Check if file needs to be hashed (based on mtime/size comparison).
# The manifest key and the path on disk differ when an offset is in play, so
# file_path overrides what is joined to base_path.
def does_file_need_to_be_hashed(src, base_path, hash_contents = None, file_path = None):
    hash_contents = {} if hash_contents is None else hash_contents
    if src not in hash_contents:
        return True
    try:
        input_file_fullpath = paths.join_paths(base_path, src if file_path is None else file_path)
        current_size = paths.get_file_size(input_file_fullpath)
        current_mtime = paths.get_file_mod_time(input_file_fullpath)
        existing = hash_contents[src]
        existing_size = int(existing.get("size", 0))
        existing_mtime = int(existing.get("mtime", 0))
        if current_size != existing_size:
            return True
        if current_mtime != existing_mtime:
            return True
        return False
    except (OSError, ValueError, TypeError):
        return True

###########################################################

# Placeholder hash data for a pretend run: empty hash, zero size and mtime
def _get_pretend_hash_data(path_dir, path_file, include_enc_fields):
    hash_data = {
        "dir": path_dir,
        "filename": path_file,
        "hash": "",
        "size": 0,
        "mtime": 0
    }
    if include_enc_fields:
        hash_data["filename_enc"] = ""
        hash_data["hash_enc"] = ""
        hash_data["size_enc"] = 0
    return hash_data

# Hash data of an encrypted file from its embedded plaintext info, with the encrypted file's
# name, MD5 and size; empty when the embedded info can't be read
def _get_encrypted_hash_data(path_full, path_dir, path_file, passphrase, verbose, pretend_run, exit_on_failure):
    hash_data = {}
    file_info = cryption.get_embedded_file_info(
        src = path_full,
        passphrase = passphrase,
        hasher = hashutil.calculate_file_xxh3,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if file_info:
        hash_data["dir"] = path_dir
        hash_data["filename"] = file_info["filename"]
        hash_data["filename_enc"] = path_file
        hash_data["hash"] = file_info["hash"]
        hash_data["hash_enc"] = hashutil.calculate_file_md5(
            src = path_full,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        hash_data["size"] = file_info["size"]
        hash_data["size_enc"] = os.path.getsize(path_full)
        hash_data["mtime"] = file_info["mtime"]
    return hash_data

# Hash data of an unencrypted file: its XXH3, size and mtime, plus a generated encrypted name
# and empty encrypted fields when requested
def _get_plain_hash_data(path_full, path_dir, path_file, include_enc_fields, verbose, pretend_run, exit_on_failure):
    hash_data = {}
    hash_data["dir"] = path_dir
    hash_data["filename"] = path_file
    hash_data["hash"] = hashutil.calculate_file_xxh3(
        src = path_full,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    hash_data["size"] = paths.get_file_size(path_full)
    hash_data["mtime"] = paths.get_file_mod_time(path_full)

    # Add enc fields if requested
    if include_enc_fields:
        hash_data["filename_enc"] = cryption.generate_encrypted_filename(path_file)
        hash_data["hash_enc"] = ""
        hash_data["size_enc"] = 0
    return hash_data

# Calculate hash for a file
def calculate_hash(
    src,
    base_path = None,
    passphrase = None,
    include_enc_fields = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get path info
    path_file = paths.get_filename_file(src)
    path_dir = paths.get_filename_directory(src)
    if base_path:
        path_full = paths.join_paths(base_path, src)
    else:
        path_full = src

    # Log action
    if verbose:
        if pretend_run:
            logger.log_info("[pretend] Would hash file %s" % path_full)
        else:
            logger.log_info("Hashing file %s ..." % path_full)

    # Handle pretend run
    if pretend_run:
        return _get_pretend_hash_data(path_dir, path_file, include_enc_fields)

    # Handle encrypted files
    if include_enc_fields and cryption.is_file_encrypted(path_full) and cryption.is_passphrase_valid(passphrase):
        return _get_encrypted_hash_data(path_full, path_dir, path_file, passphrase, verbose, pretend_run, exit_on_failure)

    # Handle unencrypted files
    return _get_plain_hash_data(path_full, path_dir, path_file, include_enc_fields, verbose, pretend_run, exit_on_failure)

# (read, write) functions for the hash file format, JSON unless it is CSV
def get_hash_file_funcs(hash_format = None):
    if hash_format is None:
        hash_format = config.HashFormatType.JSON
    if hash_format == config.HashFormatType.JSON:
        return read_hash_file_json, write_hash_file_json
    return read_hash_file_csv, write_hash_file_csv

# (file list, base path) to hash: a given list needs base_path, a directory is listed and is
# the default base; None, logged, when a list comes without a base path
def _get_hash_inputs(src, base_path):
    if isinstance(src, list):
        if not base_path:
            logger.log_error("base_path required when src is a file list")
            return None
        return src, base_path
    file_list = paths.build_file_list(src, use_relative_paths = True)
    if not base_path:
        base_path = src
    return file_list, base_path

# Keep an existing entry's non-empty encrypted fields where the new data has none, and its
# older mtime when the hash is unchanged
def _merge_existing_hash_entry(hash_data, existing):
    for enc_field in ["filename_enc", "hash_enc", "size_enc"]:
        new_value = hash_data.get(enc_field)
        existing_value = existing.get(enc_field)
        if not new_value and existing_value:
            hash_data[enc_field] = existing_value
    if hash_data.get("hash") == existing.get("hash"):
        new_mtime = int(hash_data.get("mtime", 0) or 0)
        existing_mtime = int(existing.get("mtime", 0) or 0)
        if existing_mtime and (not new_mtime or existing_mtime < new_mtime):
            hash_data["mtime"] = existing_mtime

# The manifest key for a file, under the offset when one is given
def _get_offset_hash_key(offset, file_path):
    if offset:
        return paths.join_paths(offset, file_path)
    return file_path

# Hash one listed file into hash_contents unless it is the output file or unchanged, putting
# it under the offset and merging what an existing entry already knew
def _hash_listed_file(
    file_path,
    output_file,
    hash_contents,
    base_path,
    offset,
    passphrase,
    include_enc_fields,
    verbose,
    pretend_run,
    exit_on_failure):

    # Skip the output file itself
    full_path = paths.join_paths(base_path, file_path)
    if paths.is_path_file(output_file) and os.path.realpath(full_path) == os.path.realpath(output_file):
        return

    # Check if file needs to be hashed
    hash_key = _get_offset_hash_key(offset, file_path)
    if not does_file_need_to_be_hashed(hash_key, base_path, hash_contents, file_path = file_path):
        if verbose:
            logger.log_info("Skipping (unchanged): %s" % file_path)
        return

    # Calculate hash
    hash_data = calculate_hash(
        src = file_path,
        base_path = base_path,
        passphrase = passphrase,
        include_enc_fields = include_enc_fields,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if hash_data:
        _store_hash_data(hash_contents, hash_data, offset)

# Store new hash data under its dir/filename key, its dir under the offset when one is given,
# merging what an existing entry already knew
def _store_hash_data(hash_contents, hash_data, offset):
    if offset:
        hash_data["dir"] = paths.join_paths(offset, hash_data["dir"])
    hash_key = paths.join_paths(hash_data["dir"], hash_data["filename"])
    if hash_key in hash_contents:
        _merge_existing_hash_entry(hash_data, hash_contents[hash_key])
    hash_contents[hash_key] = hash_data

# Create the output file's folder and read its existing hash entries; empty when it is not
# a file yet
def _prepare_hash_output_file(read_func, output_file, verbose, pretend_run, exit_on_failure):

    # Make sure output directory exists
    fileops.make_directory(
        src = paths.get_filename_directory(output_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Load existing hash contents
    hash_contents = {}
    if paths.is_path_file(output_file):
        hash_contents = read_func(
            src = output_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
    return hash_contents

# Run _hash_listed_file over each file in file_list, updating hash_contents
def _hash_listed_files(
    file_list, output_file, hash_contents, base_path, offset, passphrase,
    include_enc_fields, verbose, pretend_run, exit_on_failure):
    for file_path in file_list:
        _hash_listed_file(
            file_path, output_file, hash_contents, base_path, offset, passphrase,
            include_enc_fields, verbose, pretend_run, exit_on_failure)

# Hash files in a directory and write to output file
def hash_files(
    src,
    output_file,
    base_path = None,
    offset = None,
    passphrase = None,
    hash_format = None,
    include_enc_fields = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Determine read/write functions, then base path and file list
    read_func, write_func = get_hash_file_funcs(hash_format)
    hash_inputs = _get_hash_inputs(src, base_path)
    if hash_inputs is None:
        return False
    file_list, base_path = hash_inputs

    # Make sure output directory exists and load existing hash contents
    hash_contents = _prepare_hash_output_file(read_func, output_file, verbose, pretend_run, exit_on_failure)

    # Hash each file
    _hash_listed_files(
        file_list, output_file, hash_contents, base_path, offset, passphrase,
        include_enc_fields, verbose, pretend_run, exit_on_failure)

    # Write hash file
    if not pretend_run and hash_contents:
        return write_func(
            src = output_file,
            hash_contents = hash_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# Remove the entries whose files are missing under locker_root; whether any were removed
def remove_missing_hash_entries(hash_contents, locker_root, verbose = False):
    modified = False
    for key in list(hash_contents.keys()):
        entry = hash_contents[key]
        file_path = paths.join_paths(locker_root, entry["dir"], entry["filename"])
        if not paths.is_path_file(file_path):
            if verbose:
                logger.log_info("Removing (missing): %s" % key)
            del hash_contents[key]
            modified = True
    return modified

# Clean hash entries for files that no longer exist on disk
def clean_missing_hash_entries(
    hash_file,
    locker_root,
    hash_format = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Determine read/write functions
    read_func, write_func = get_hash_file_funcs(hash_format)

    # Read hash file
    if not paths.is_path_file(hash_file):
        return True
    hash_contents = read_func(
        src = hash_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check each entry and remove if file doesn't exist
    modified = remove_missing_hash_entries(hash_contents, locker_root, verbose)

    # Write hash file if modified
    if modified and not pretend_run:
        return write_func(
            src = hash_file,
            hash_contents = hash_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# hashutil function name for each hash type build_hash_map supports; any other type uses MD5
HASH_FUNC_NAMES = (
    (config.HashType.MD5, "calculate_file_md5"),
    (config.HashType.SHA1, "calculate_file_sha1"),
    (config.HashType.XXH3, "calculate_file_xxh3"),
    (config.HashType.SHA256, "calculate_file_sha256"),
    (config.HashType.CRC32, "calculate_file_crc32"))

# The hashutil file hash function for the hash type, MD5 when it is not supported
def get_hash_func(hash_type):
    for supported_type, func_name in HASH_FUNC_NAMES:
        if hash_type == supported_type:
            return getattr(hashutil, func_name)
    return hashutil.calculate_file_md5

# A hash map entry for one file: name, directory, hash, size and mtime
def _build_hash_map_entry(full_path, rel_path, hash_func, pretend_run, exit_on_failure):

    # Get file info
    file_size = paths.get_file_size(full_path)
    file_mtime = paths.get_file_mod_time(full_path)
    file_name = paths.get_filename_file(rel_path)
    file_dir = paths.get_filename_directory(rel_path)

    # Calculate hash
    file_hash = hash_func(
        src = full_path,
        verbose = False,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return {
        "filename": file_name,
        "dir": file_dir,
        "hash": file_hash,
        "size": file_size,
        "mtime": file_mtime
    }

# The hash map entry for a listed path; None when it is excluded or not a file
def _get_hash_map_file_entry(src_path, rel_path, excludes, hash_func, pretend_run, exit_on_failure):

    # Check exclusions
    if paths.matches_exclude_pattern(rel_path, excludes):
        return None

    # Skip if not a file
    full_path = paths.join_paths(src_path, rel_path)
    if not paths.is_path_file(full_path):
        return None

    # Calculate hash
    return _build_hash_map_entry(full_path, rel_path, hash_func, pretend_run, exit_on_failure)

# Hash every file under a path with the chosen algorithm (MD5 by default), keyed by relative path with size and mtime; empty when the path is missing
def build_hash_map(
    src_path,
    hash_type = None,
    excludes = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get excludes
    excludes = [] if excludes is None else excludes

    # Check source path
    hash_map = {}
    if not paths.does_path_exist(src_path):
        logger.log_warning("Path does not exist: %s" % src_path)
        return hash_map

    # Determine hash function, defaulting to MD5
    hash_func = get_hash_func(hash_type)

    # Build file list
    file_list = paths.build_file_list(src_path, use_relative_paths = True)
    total_files = len(file_list)

    # Build hash map
    if verbose:
        logger.log_info("Building hash map for: %s" % src_path)
    for idx, rel_path in enumerate(file_list):
        hash_map_entry = _get_hash_map_file_entry(src_path, rel_path, excludes, hash_func, pretend_run, exit_on_failure)
        if hash_map_entry is None:
            continue
        hash_map[rel_path] = hash_map_entry
        if verbose and (idx + 1) % 100 == 0:
            logger.log_info("Processed %d/%d files" % (idx + 1, total_files))
    if verbose:
        logger.log_info("Hash map complete: %d files" % len(hash_map))
    return hash_map

###########################################################

# Locker hash files
###########################################################

# The stripped, non-empty glob patterns of a comma-separated filter; none for no filter
def _split_filter_patterns(filter_text):
    return [p.strip() for p in filter_text.split(",") if p.strip()] if filter_text else []

# The relative locker files the filters keep: hidden ones dropped unless included, then only
# those matching an include pattern, then none matching an exclude pattern
def filter_locker_files(file_list, include_patterns = (), exclude_patterns = (), include_hidden = False):
    if not include_hidden:
        file_list = [f for f in file_list if not any(part.startswith(".") for part in f.split(os.sep))]
    if include_patterns:
        file_list = [f for f in file_list if any(fnmatch.fnmatch(f, p) for p in include_patterns)]
    if exclude_patterns:
        file_list = [f for f in file_list if not any(fnmatch.fnmatch(f, p) for p in exclude_patterns)]
    return file_list

# Log the locker, the hash file root and any filter patterns
def _log_locker_hash_sources(base_dir, include_patterns, exclude_patterns):
    logger.log_info("Source: %s" % base_dir)
    logger.log_info("FileMetadata: %s" % environment.get_file_locker_hashes_root_dir())
    if include_patterns:
        logger.log_info("Include patterns: %s" % include_patterns)
    if exclude_patterns:
        logger.log_info("Exclude patterns: %s" % exclude_patterns)

# Hash each group of locker files into its CSV; (hash files written, hash files that failed)
def _write_locker_hash_groups(files_by_hash_file, base_dir, verbose = False, pretend_run = False):
    hash_files_processed = []
    failed_hash_files = []
    for hash_file, files in files_by_hash_file.items():
        logger.log_info("Processing: %s (%d files)" % (hash_file, len(files)))
        success = hash_files(
            src = files,
            output_file = hash_file,
            base_path = base_dir,
            hash_format = config.HashFormatType.CSV,
            include_enc_fields = False,
            verbose = verbose,
            pretend_run = pretend_run)
        if not success:
            logger.log_error("  Failed to write: %s" % hash_file)
            failed_hash_files.append(hash_file)
            continue
        hash_files_processed.append(hash_file)
        logger.log_info("  Wrote: %s" % hash_file)
    return hash_files_processed, failed_hash_files

# Drop the entries of files gone from the locker from each hash file; the ones that failed
def _clean_locker_hash_files(hash_file_list, base_dir, verbose = False, pretend_run = False):
    failed_hash_files = []
    logger.log_info("Cleaning missing entries...")
    for hash_file in hash_file_list:
        success = clean_missing_hash_entries(
            hash_file = hash_file,
            locker_root = base_dir,
            hash_format = config.HashFormatType.CSV,
            verbose = verbose,
            pretend_run = pretend_run)
        if not success:
            logger.log_error("Failed to clean: %s" % hash_file)
            failed_hash_files.append(hash_file)
    return failed_hash_files

# The relative file paths grouped under the locker hash file each belongs to at depth
def _group_files_by_hash_file(file_list, depth):
    files_by_hash_file = {}
    for file_path in file_list:
        hash_file = environment.get_file_locker_hashes_file(file_path, depth = depth)
        files_by_hash_file.setdefault(hash_file, []).append(file_path)
    return files_by_hash_file

# Write the XXH3 hash, size and mtime of each filtered file in the locker directory to CSVs
# grouped by its leading folders, quitting on a bad depth or directory; False, logged, when any
# hash file could not be written or cleaned
def hash_locker_files(locker_base_directory, include_filter = None, exclude_filter = None, include_hidden = False, depth = 2, verbose = False, pretend_run = False):
    if depth < 1:
        logger.log_error("Depth must be at least 1", quit_program = True)
    base_dir = paths.expand_path(locker_base_directory)
    if not paths.does_path_exist(base_dir):
        logger.log_error("Base directory does not exist: %s" % base_dir, quit_program = True)
    include_patterns = _split_filter_patterns(include_filter)
    exclude_patterns = _split_filter_patterns(exclude_filter)
    _log_locker_hash_sources(base_dir, include_patterns, exclude_patterns)

    # Gather the filtered files
    logger.log_info("Scanning files...")
    file_list = paths.build_file_list(base_dir, use_relative_paths = True)
    file_list = filter_locker_files(file_list, include_patterns, exclude_patterns, include_hidden = include_hidden)
    logger.log_info("Found %d files" % len(file_list))

    # Write and clean the hash files
    hash_files_processed, failed_hash_files = _write_locker_hash_groups(_group_files_by_hash_file(file_list, depth), base_dir, verbose = verbose, pretend_run = pretend_run)
    failed_hash_files += _clean_locker_hash_files(hash_files_processed, base_dir, verbose = verbose, pretend_run = pretend_run)
    if failed_hash_files:
        logger.log_error("%d hash files could not be written" % len(failed_hash_files))
        return False
    logger.log_info("Done!")
    return True
