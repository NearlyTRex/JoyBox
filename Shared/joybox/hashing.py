# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import fileops
from joybox import hashutil
from joybox import logger
from joybox import paths
from joybox import serialization
from joybox import cryption

###########################################################

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

# Normalize hash entry to ensure all fields exist with correct types
def normalize_hash_entry(data):
    normalized = dict(data)

    # Ensure string fields exist
    if "dir" not in normalized:
        normalized["dir"] = ""
    if "filename" not in normalized:
        normalized["filename"] = ""
    if "filename_enc" not in normalized:
        normalized["filename_enc"] = ""
    if "hash" not in normalized:
        normalized["hash"] = ""
    if "hash_enc" not in normalized:
        normalized["hash_enc"] = ""

    # Ensure size fields are int
    if "size" not in normalized:
        normalized["size"] = 0
    elif isinstance(normalized["size"], str):
        try:
            normalized["size"] = int(normalized["size"])
        except ValueError:
            normalized["size"] = 0
    if "size_enc" not in normalized:
        normalized["size_enc"] = 0
    elif isinstance(normalized["size_enc"], str):
        try:
            normalized["size_enc"] = int(normalized["size_enc"])
        except ValueError:
            normalized["size_enc"] = 0

    # Ensure mtime is int
    if "mtime" not in normalized:
        normalized["mtime"] = 0
    elif isinstance(normalized["mtime"], str):
        try:
            normalized["mtime"] = int(normalized["mtime"])
        except ValueError:
            normalized["mtime"] = 0
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

    # Calculate hash data
    hash_data = {}

    # Handle encrypted files
    if include_enc_fields and cryption.is_file_encrypted(path_full) and cryption.is_passphrase_valid(passphrase):
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
    else:
        # Handle unencrypted files
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

    # Default to JSON format
    if hash_format is None:
        hash_format = config.HashFormatType.JSON

    # Determine read/write functions
    read_func = read_hash_file_json if hash_format == config.HashFormatType.JSON else read_hash_file_csv
    write_func = write_hash_file_json if hash_format == config.HashFormatType.JSON else write_hash_file_csv

    # Determine base path and file list
    if isinstance(src, list):
        file_list = src
        if not base_path:
            logger.log_error("base_path required when src is a file list")
            return False
    else:
        file_list = paths.build_file_list(src, use_relative_paths = True)
        if not base_path:
            base_path = src

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

    # Hash each file
    for file_path in file_list:
        full_path = paths.join_paths(base_path, file_path)

        # Skip the output file itself
        if paths.is_path_file(output_file) and os.path.realpath(full_path) == os.path.realpath(output_file):
            continue

        # Determine hash entry key (with offset prefix if provided)
        if offset:
            hash_key = paths.join_paths(offset, file_path)
        else:
            hash_key = file_path

        # Check if file needs to be hashed
        if not does_file_need_to_be_hashed(hash_key, base_path, hash_contents, file_path = file_path):
            if verbose:
                logger.log_info("Skipping (unchanged): %s" % file_path)
            continue

        # Calculate hash
        hash_data = calculate_hash(
            src = file_path,
            base_path = base_path,
            passphrase = passphrase,
            include_enc_fields = include_enc_fields,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Update dir field to include offset
        if hash_data and offset:
            hash_data["dir"] = paths.join_paths(offset, hash_data["dir"])

        # Store hash data (preserve existing _enc fields if new ones are empty, keep oldest mtime if hash matches)
        if hash_data:
            hash_key = paths.join_paths(hash_data["dir"], hash_data["filename"])
            if hash_key in hash_contents:
                existing = hash_contents[hash_key]
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
            hash_contents[hash_key] = hash_data

    # Write hash file
    if not pretend_run and hash_contents:
        return write_func(
            src = output_file,
            hash_contents = hash_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

# Clean hash entries for files that no longer exist on disk
def clean_missing_hash_entries(
    hash_file,
    locker_root,
    hash_format = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Default to JSON format
    if hash_format is None:
        hash_format = config.HashFormatType.JSON

    # Determine read/write functions
    read_func = read_hash_file_json if hash_format == config.HashFormatType.JSON else read_hash_file_csv
    write_func = write_hash_file_json if hash_format == config.HashFormatType.JSON else write_hash_file_csv

    # Read hash file
    if not paths.is_path_file(hash_file):
        return True
    hash_contents = read_func(
        src = hash_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check each entry and remove if file doesn't exist
    modified = False
    for key in list(hash_contents.keys()):
        entry = hash_contents[key]
        file_path = paths.join_paths(locker_root, entry["dir"], entry["filename"])
        if not paths.is_path_file(file_path):
            if verbose:
                logger.log_info("Removing (missing): %s" % key)
            del hash_contents[key]
            modified = True

    # Write hash file if modified
    if modified and not pretend_run:
        return write_func(
            src = hash_file,
            hash_contents = hash_contents,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

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

    # Default to MD5
    if hash_type is None:
        hash_type = config.HashType.MD5

    # Check source path
    hash_map = {}
    if not paths.does_path_exist(src_path):
        logger.log_warning("Path does not exist: %s" % src_path)
        return hash_map

    # Determine hash function
    if hash_type == config.HashType.MD5:
        hash_func = hashutil.calculate_file_md5
    elif hash_type == config.HashType.SHA1:
        hash_func = hashutil.calculate_file_sha1
    elif hash_type == config.HashType.XXH3:
        hash_func = hashutil.calculate_file_xxh3
    elif hash_type == config.HashType.SHA256:
        hash_func = hashutil.calculate_file_sha256
    elif hash_type == config.HashType.CRC32:
        hash_func = hashutil.calculate_file_crc32
    else:
        hash_func = hashutil.calculate_file_md5

    # Build file list
    file_list = paths.build_file_list(src_path, use_relative_paths = True)
    total_files = len(file_list)

    # Build hash map
    if verbose:
        logger.log_info("Building hash map for: %s" % src_path)
    for idx, rel_path in enumerate(file_list):

        # Check exclusions
        if paths.matches_exclude_pattern(rel_path, excludes):
            continue

        # Skip if not a file
        full_path = paths.join_paths(src_path, rel_path)
        if not paths.is_path_file(full_path):
            continue

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
        hash_map[rel_path] = {
            "filename": file_name,
            "dir": file_dir,
            "hash": file_hash,
            "size": file_size,
            "mtime": file_mtime
        }
        if verbose and (idx + 1) % 100 == 0:
            logger.log_info("Processed %d/%d files" % (idx + 1, total_files))
    if verbose:
        logger.log_info("Hash map complete: %d files" % len(hash_map))
    return hash_map

###########################################################
