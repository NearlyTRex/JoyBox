# Imports
import os, os.path
import sys
import csv
import zlib
import hashlib

# Local imports
import config
import environment
import fileops
import system
import logger
import paths
import serialization
import archive
import cryption
import datautils

###########################################################

# Calculate string crc32
def calculate_string_crc32(string):
    if isinstance(string, str):
        string = string.encode("utf8")
    return "%x" % zlib.crc32(string)

# Calculate string md5
def calculate_string_md5(string):
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.md5(string).hexdigest()

# Calculate string sha1
def calculate_string_sha1(string):
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.sha1(string).hexdigest()

# Calculate string sha256
def calculate_string_sha256(string):
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.sha256(string).hexdigest()

# Calculate string XXH3
def calculate_string_xxh3(string):
    import xxhash
    return xxhash.xxh3_64(string).hexdigest()

###########################################################

# Calculate file crc32
def calculate_file_crc32(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            if verbose:
                logger.log_info("[pretend] Would calculate crc32 for %s" % src)
            return ""
        if verbose:
            logger.log_info("Calculating crc32 for %s" % src)
        with open(src, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(src)
            percent_done = 0
            checksum = 0
            if verbose:
                logger.log_percent_complete(percent_done)
            while (chunk := file.read(chunksize)):
                checksum = zlib.crc32(chunk, checksum)
                if verbose:
                    read_size += len(chunk)
                    percent_done = int(round(100 * read_size / total_size))
                    logger.log_percent_complete(percent_done)
            return "%x" % checksum
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate crc32 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file md5
def calculate_file_md5(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            if verbose:
                logger.log_info("[pretend] Would calculate md5 for %s" % src)
            return ""
        if verbose:
            logger.log_info("Calculating md5 for %s" % src)
        with open(src, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(src)
            percent_done = 0
            md5_hash = hashlib.md5()
            if verbose:
                logger.log_percent_complete(percent_done)
            for chunk in iter(lambda: file.read(chunksize),b""):
                md5_hash.update(chunk)
                if verbose:
                    read_size += len(chunk)
                    percent_done = int(round(100 * read_size / total_size))
                    logger.log_percent_complete(percent_done)
            return md5_hash.hexdigest()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate md5 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file sha1
def calculate_file_sha1(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            if verbose:
                logger.log_info("[pretend] Would calculate sha1 for %s" % src)
            return ""
        if verbose:
            logger.log_info("Calculating sha1 for %s" % src)
        with open(src, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(src)
            percent_done = 0
            sha1_hash = hashlib.sha1()
            if verbose:
                logger.log_percent_complete(percent_done)
            for chunk in iter(lambda: file.read(chunksize),b""):
                sha1_hash.update(chunk)
                if verbose:
                    read_size += len(chunk)
                    percent_done = int(round(100 * read_size / total_size))
                    logger.log_percent_complete(percent_done)
            return sha1_hash.hexdigest()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate sha1 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file sha256
def calculate_file_sha256(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            if verbose:
                logger.log_info("[pretend] Would calculate sha256 for %s" % src)
            return ""
        if verbose:
            logger.log_info("Calculating sha256 for %s" % src)
        with open(src, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(src)
            percent_done = 0
            sha256_hash = hashlib.sha256()
            if verbose:
                logger.log_percent_complete(percent_done)
            for chunk in iter(lambda: file.read(chunksize),b""):
                sha256_hash.update(chunk)
                if verbose:
                    read_size += len(chunk)
                    percent_done = int(round(100 * read_size / total_size))
                    logger.log_percent_complete(percent_done)
            return sha256_hash.hexdigest()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate sha256 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file xxh3
def calculate_file_xxh3(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if pretend_run:
            if verbose:
                logger.log_info("[pretend] Would calculate xxh3 for %s" % src)
            return ""
        if verbose:
            logger.log_info("Calculating xxh3 for %s" % src)
        import xxhash
        with open(src, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(src)
            percent_done = 0
            xxh3_hash = xxhash.xxh3_64()
            if verbose:
                logger.log_percent_complete(percent_done)
            for chunk in iter(lambda: file.read(chunksize),b""):
                xxh3_hash.update(chunk)
                if verbose:
                    read_size += len(chunk)
                    percent_done = int(round(100 * read_size / total_size))
                    logger.log_percent_complete(percent_done)
            return xxh3_hash.hexdigest()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate xxh3 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

###########################################################

# Find duplicate files in the search directory
def find_duplicate_files(
    filename,
    directory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    found_files = []
    test_checksum = calculate_file_crc32(filename, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    for obj in paths.get_directory_contents(directory):
        obj_path = paths.join_paths(directory, obj)
        if paths.is_path_file(obj_path):
            obj_checksum = calculate_file_crc32(obj_path, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
            if test_checksum == obj_checksum:
                found_files.append(obj_path)
    return found_files

# Find duplicate archives in the search directory
def find_duplicate_archives(
    filename,
    directory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    found_files = []
    test_checksums = archive.get_archive_checksums(filename)
    for obj in paths.get_directory_contents(directory):
        obj_path = paths.join_paths(directory, obj)
        if paths.is_path_file(obj_path):
            obj_checksums = archive.get_archive_checksums(obj_path)
            if [i for i in test_checksums if i not in obj_checksums] == []:
                found_files.append(obj_path)
    return found_files

# Check if plain files are identical
def are_plain_files_identical(
    first,
    second,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    first_exists = paths.does_path_exist(first, case_sensitive_paths = case_sensitive_paths)
    second_exists = paths.does_path_exist(second, case_sensitive_paths = case_sensitive_paths)
    if first_exists and second_exists:
        first_crc32 = calculate_file_crc32(first, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        second_crc32 = calculate_file_crc32(second, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        return first_crc32 == second_crc32
    return False

# Check if archive files are identical
def are_archive_files_identical(
    first,
    second,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    first_is_archive = archive.is_archive(first)
    second_is_archive = archive.is_archive(second)
    if first_is_archive and second_is_archive:
        first_checksums = sorted(archive.get_archive_checksums(first), key=lambda item: (item['path'], item['crc']))
        second_checksums = sorted(archive.get_archive_checksums(second), key=lambda item: (item['path'], item['crc']))
        if len(first_checksums) > 0 and len(second_checksums) > 0:
            return first_checksums == second_checksums
    return False

# Check if files are identical
def are_files_identical(
    first,
    second,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Compare as plain files
    identical = are_plain_files_identical(
        first = first,
        second = second,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if identical:
        return True

    # Compare as archive files
    identical = are_archive_files_identical(
        first = first,
        second = second,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if identical:
        return True

    # These are different files
    return False

# Get file groupings
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
    previous_basename = ""
    current_basename = ""

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
            if not file_directory in hash_sets:
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
        if hash_set_size + results[group_name]["size"] > max_group_size:
            group_counter += 1
            group_name = "Group" + str(group_counter)
            add_empty_group(group_name)

        # Add to group
        results[group_name]["size"] += hash_set_size
        results[group_name]["files"] += hash_set_files

    # Return groups
    return results

###########################################################

# Read json hash file
def read_hash_file_json(
    src,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    json_hashes = serialization.read_json_file(
        src = src,
        verbose = verbose,
        pretend_run = pretend_run,
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

# Write json hash file
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

# Read csv hash file
def read_hash_file_csv(
    src,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    hash_contents = {}
    try:
        if verbose:
            logger.log_info("Reading CSV hash file: %s" % src)
        if not paths.does_path_exist(src):
            return hash_contents
        with open(src, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_location = paths.join_paths(row["dir"], row["filename"])
                hash_contents[file_location] = {
                    "dir": row["dir"],
                    "filename": row["filename"],
                    "hash": row["hash"],
                    "size": int(row["size"]),
                    "mtime": int(row["mtime"])
                }
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read CSV hash file: %s" % src)
            logger.log_error(e, quit_program = True)
    return hash_contents

# Write csv hash file
def write_hash_file_csv(
    src,
    hash_contents,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing CSV hash file: %s" % src)
        if pretend_run:
            return True
        fileops.make_directory(
            src = paths.get_filename_directory(src),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        with open(src, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["dir", "filename", "hash", "size", "mtime"])
            writer.writeheader()
            for hash_key in sorted(hash_contents.keys()):
                data = hash_contents[hash_key]
                writer.writerow({
                    "dir": data["dir"],
                    "filename": data["filename"],
                    "hash": data["hash"],
                    "size": data["size"],
                    "mtime": data["mtime"]
                })
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write CSV hash file: %s" % src)
            logger.log_error(e, quit_program = True)
        return False

# Sort hash file
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
        pretend_run = pretend_run,
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

# Check if file needs to be hashed (based on mtime/size comparison)
def does_file_need_to_be_hashed(src, base_path, hash_contents = {}):
    if src not in hash_contents:
        return True
    try:
        input_file_fullpath = paths.join_paths(base_path, src)
        current_size = os.path.getsize(input_file_fullpath)
        current_mtime = int(os.path.getmtime(input_file_fullpath))
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
            hasher = calculate_file_xxh3,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if file_info:
            hash_data["dir"] = path_dir
            hash_data["filename"] = file_info["filename"]
            hash_data["filename_enc"] = path_file
            hash_data["hash"] = file_info["hash"]
            hash_data["hash_enc"] = calculate_file_md5(
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
        hash_data["hash"] = calculate_file_xxh3(
            src = path_full,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        hash_data["size"] = os.path.getsize(path_full)
        hash_data["mtime"] = int(os.path.getmtime(path_full))

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
            pretend_run = pretend_run,
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
        if not does_file_need_to_be_hashed(hash_key, base_path, hash_contents):
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
        pretend_run = pretend_run,
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

###########################################################
