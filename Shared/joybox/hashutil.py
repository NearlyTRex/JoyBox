# Hashing strings and files, and telling files apart by their contents: plain
# files by checksum, zip archives by the checksums of what they hold.

# Imports
import os
import zlib
import hashlib

# Local imports
from joybox import archiveinfo
from joybox import config
from joybox import logger
from joybox import paths
from joybox import serialization

# Calculate string crc32
def calculate_string_crc32(string):
    if isinstance(string, str):
        string = string.encode("utf8")
    return "%08x" % zlib.crc32(string)

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

# Calculate file crc32
def calculate_file_crc32(
    src,
    chunksize = config.HASH_CHUNK_SIZE,
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
        read_size = 0
        total_size = os.path.getsize(src)
        percent_done = 0
        checksum = 0
        if verbose:
            logger.log_percent_complete(percent_done)
        for chunk in serialization.read_binary_chunks(src, chunksize):
            checksum = zlib.crc32(chunk, checksum)
            if verbose:
                read_size += len(chunk)
                percent_done = int(round(100 * read_size / total_size))
                logger.log_percent_complete(percent_done)
        return "%08x" % checksum
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to calculate crc32 for %s" % src)
            logger.log_error(e, quit_program = True)
        return ""

# Calculate file md5
def calculate_file_md5(
    src,
    chunksize = config.HASH_CHUNK_SIZE,
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
        read_size = 0
        total_size = os.path.getsize(src)
        percent_done = 0
        md5_hash = hashlib.md5()
        if verbose:
            logger.log_percent_complete(percent_done)
        for chunk in serialization.read_binary_chunks(src, chunksize):
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
    chunksize = config.HASH_CHUNK_SIZE,
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
        read_size = 0
        total_size = os.path.getsize(src)
        percent_done = 0
        sha1_hash = hashlib.sha1()
        if verbose:
            logger.log_percent_complete(percent_done)
        for chunk in serialization.read_binary_chunks(src, chunksize):
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
    chunksize = config.HASH_CHUNK_SIZE,
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
        read_size = 0
        total_size = os.path.getsize(src)
        percent_done = 0
        sha256_hash = hashlib.sha256()
        if verbose:
            logger.log_percent_complete(percent_done)
        for chunk in serialization.read_binary_chunks(src, chunksize):
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
    chunksize = config.HASH_CHUNK_SIZE,
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
        read_size = 0
        total_size = os.path.getsize(src)
        percent_done = 0
        xxh3_hash = xxhash.xxh3_64()
        if verbose:
            logger.log_percent_complete(percent_done)
        for chunk in serialization.read_binary_chunks(src, chunksize):
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
    directory):
    found_files = []
    test_checksums = sorted(archiveinfo.get_archive_checksums(filename), key = lambda item: (item["path"], item["crc"]))
    if not test_checksums:
        return found_files
    for obj in paths.get_directory_contents(directory):
        obj_path = paths.join_paths(directory, obj)
        if paths.is_path_file(obj_path):
            obj_checksums = sorted(archiveinfo.get_archive_checksums(obj_path), key = lambda item: (item["path"], item["crc"]))
            if obj_checksums == test_checksums:
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
    second):
    first_is_archive = archiveinfo.is_archive(first)
    second_is_archive = archiveinfo.is_archive(second)
    if first_is_archive and second_is_archive:
        first_checksums = sorted(archiveinfo.get_archive_checksums(first), key=lambda item: (item['path'], item['crc']))
        second_checksums = sorted(archiveinfo.get_archive_checksums(second), key=lambda item: (item['path'], item['crc']))
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
        second = second)
    if identical:
        return True

    # These are different files
    return False
