# Imports
import os, os.path
import sys

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
def CalculateStringCRC32(string):
    import zlib
    if isinstance(string, str):
        string = string.encode("utf8")
    return "%x" % zlib.crc32(string)

# Calculate string md5
def CalculateStringMD5(string):
    import hashlib
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.md5(string).hexdigest()

# Calculate string sha1
def CalculateStringSHA1(string):
    import hashlib
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.sha1(string).hexdigest()

# Calculate string sha256
def CalculateStringSHA256(string):
    import hashlib
    if isinstance(string, str):
        string = string.encode("utf8")
    return hashlib.sha256(string).hexdigest()

# Calculate string XXH3
def CalculateStringXXH3(string):
    import xxhash
    return xxhash.xxh3_64(string).hexdigest()

###########################################################

# Calculate file crc32
def CalculateFileCRC32(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Calculating crc32 for %s" % src)
        if not pretend_run:
            import zlib
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
        return ""
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate crc32 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file md5
def CalculateFileMD5(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Calculating md5 for %s" % src)
        if not pretend_run:
            import hashlib
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
        return ""
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate md5 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file sha1
def CalculateFileSHA1(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Calculating sha1 for %s" % src)
        if not pretend_run:
            import hashlib
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
        return ""
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate sha1 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file sha256
def CalculateFileSHA256(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Calculating sha256 for %s" % src)
        if not pretend_run:
            import hashlib
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
        return ""
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate sha256 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file xxh3
def CalculateFileXXH3(
    src,
    chunksize = config.hash_chunk_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Calculating xxh3 for %s" % src)
        if not pretend_run:
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
        return ""
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate xxh3 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

###########################################################

# Find duplicate files in the search directory
def FindDuplicateFiles(
    filename,
    directory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    found_files = []
    test_checksum = CalculateFileCRC32(filename, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
    for obj in paths.get_directory_contents(directory):
        obj_path = paths.join_paths(directory, obj)
        if paths.is_path_file(obj_path):
            obj_checksum = CalculateFileCRC32(obj_path, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
            if test_checksum == obj_checksum:
                found_files.append(obj_path)
    return found_files

# Find duplicate archives in the search directory
def FindDuplicateArchives(
    filename,
    directory,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    found_files = []
    test_checksums = archive.GetArchiveChecksums(filename)
    for obj in paths.get_directory_contents(directory):
        obj_path = paths.join_paths(directory, obj)
        if paths.is_path_file(obj_path):
            obj_checksums = archive.GetArchiveChecksums(obj_path)
            if [i for i in test_checksums if i not in obj_checksums] == []:
                found_files.append(obj_path)
    return found_files

# Check if plain files are identical
def ArePlainFilesIdentical(
    first,
    second,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    first_exists = paths.does_path_exist(first, case_sensitive_paths = case_sensitive_paths)
    second_exists = paths.does_path_exist(second, case_sensitive_paths = case_sensitive_paths)
    if first_exists and second_exists:
        first_crc32 = CalculateFileCRC32(first, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        second_crc32 = CalculateFileCRC32(second, verbose = verbose, pretend_run = pretend_run, exit_on_failure = exit_on_failure)
        return first_crc32 == second_crc32
    return False

# Check if archive files are identical
def AreArchiveFilesIdentical(
    first,
    second,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    first_is_archive = archive.IsArchive(first)
    second_is_archive = archive.IsArchive(second)
    if first_is_archive and second_is_archive:
        first_checksums = sorted(archive.GetArchiveChecksums(first), key=lambda item: (item['path'], item['crc']))
        second_checksums = sorted(archive.GetArchiveChecksums(second), key=lambda item: (item['path'], item['crc']))
        if len(first_checksums) > 0 and len(second_checksums) > 0:
            return first_checksums == second_checksums
    return False

# Check if files are identical
def AreFilesIdentical(
    first,
    second,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Compare as plain files
    identical = ArePlainFilesIdentical(
        first = first,
        second = second,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if identical:
        return True

    # Compare as archive files
    identical = AreArchiveFilesIdentical(
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
def GetFileGroupings(filenames, max_group_size):

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
        hash_contents = ReadHashFile(hash_filename)
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

# Read hash file
def ReadHashFile(
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
                json_hash["filename_enc"] = cryption.GenerateEncryptedFilename(json_hash["filename"])
            if "hash_enc" not in json_hash:
                json_hash["hash_enc"] = ""
            if "size_enc" not in json_hash:
                json_hash["size_enc"] = 0
            file_location = paths.join_paths(json_hash["dir"], json_hash["filename"])
            hash_contents[file_location] = json_hash
    return hash_contents

# Write hash file
def WriteHashFile(
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

# Sort hash file
def SortHashFile(
    src,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if verbose:
        logger.log_info("Sorting hash file %s" % src)
    hash_contents = ReadHashFile(
        src = src,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return WriteHashFile(
        src = src,
        hash_contents = hash_contents,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Check if file needs to be hashed
def DoesFileNeedToBeHashed(src, base_path, hash_contents = {}):
    if src not in hash_contents.keys():
        return True
    input_file_fullpath = paths.join_paths(base_path, src)
    input_file_size = str(os.path.getsize(input_file_fullpath))
    input_file_mtime = str(int(os.path.getmtime(input_file_fullpath)))
    if input_file_size != hash_contents[src]["size"]:
        return True
    if input_file_mtime != hash_contents[src]["mtime"]:
        return True
    return False

###########################################################

# Calculate hash
def CalculateHash(
    src,
    base_path,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get path info
    path_file = paths.get_filename_file(src)
    path_dir = paths.get_filename_directory(src)
    path_full = paths.join_paths(base_path, path_dir, path_file)
    logger.log_info("Hashing file %s ..." % path_full)

    # Create hash data
    hash_data = {}
    if cryption.IsFileEncrypted(path_full) and cryption.IsPassphraseValid(passphrase):
        file_info = cryption.GetEmbeddedFileInfo(
            src = path_full,
            passphrase = passphrase,
            hasher = CalculateFileXXH3,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if file_info:
            hash_data["dir"] = path_dir
            hash_data["filename"] = file_info["filename"]
            hash_data["filename_enc"] = path_file
            hash_data["hash"] = file_info["hash"]
            hash_data["hash_enc"] = CalculateFileMD5(
                src = path_full,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            hash_data["size"] = file_info["size"]
            hash_data["size_enc"] = os.path.getsize(path_full)
            hash_data["mtime"] = file_info["mtime"]
    else:
        hash_data["dir"] = path_dir
        hash_data["filename"] = path_file
        hash_data["filename_enc"] = cryption.GenerateEncryptedFilename(path_file)
        hash_data["hash"] = CalculateFileXXH3(
            src = path_full,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        hash_data["hash_enc"] = ""
        hash_data["size"] = os.path.getsize(path_full)
        hash_data["size_enc"] = 0
        hash_data["mtime"] = int(os.path.getmtime(path_full))

    # Return hash data
    return hash_data

# Hash files
def HashFiles(
    src,
    offset,
    output_file,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make sure directory exists
    fileops.make_directory(
        src = paths.get_filename_directory(output_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get hash contents
    hash_contents = {}
    if paths.is_path_file(output_file):
        hash_contents = ReadHashFile(
            src = output_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Hash each file in the input path
    for file in paths.build_file_list(src):
        if os.path.realpath(file) == os.path.realpath(output_file):
            continue

        # Split by base path
        file_parts = paths.split_file_path(file, offset)
        if len(file_parts) != 2:
            continue

        # Check if file needs to be hashed
        relative_base = file_parts[0]
        relative_file = paths.join_paths(offset, file_parts[1])
        if DoesFileNeedToBeHashed(relative_file, relative_base, hash_contents):

            # Calculate hash
            hash_data = CalculateHash(
                src = relative_file,
                base_path = relative_base,
                passphrase = passphrase,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            hash_entry_key = paths.join_paths(hash_data["dir"], hash_data["filename"])

            # Merge hash
            if hash_entry_key in hash_contents:
                different_hash = hash_contents[hash_entry_key]["hash"] == hash_data["hash"]
                different_size = int(hash_contents[hash_entry_key]["size"]) == int(hash_data["size"])
                different_hash_enc = hash_contents[hash_entry_key]["hash_enc"] == hash_data["hash_enc"]
                different_size_enc = int(hash_contents[hash_entry_key]["size_enc"]) == int(hash_data["size_enc"])
                if different_hash or different_size or different_hash_enc or different_size_enc:
                    hash_contents[hash_entry_key] = datautils.merge_dictionaries(
                        dict1 = hash_contents[hash_entry_key],
                        dict2 = hash_data,
                        merge_type = config.MergeType.REPLACE)
            else:
                hash_contents[hash_entry_key] = hash_data

            # Write hash file
            success = WriteHashFile(
                src = output_file,
                hash_contents = hash_contents,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Write hash file
    return WriteHashFile(
        src = output_file,
        hash_contents = hash_contents,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
