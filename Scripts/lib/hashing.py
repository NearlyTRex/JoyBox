# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import archive
import cryption

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
            system.LogInfo("Calculating crc32 for %s" % src)
        if not pretend_run:
            import zlib
            with open(src, "rb") as file:
                read_size = 0
                total_size = os.path.getsize(src)
                percent_done = 0
                checksum = 0
                if verbose:
                    system.LogPercentComplete(percent_done)
                while (chunk := file.read(chunksize)):
                    checksum = zlib.crc32(chunk, checksum)
                    if verbose:
                        read_size += len(chunk)
                        percent_done = int(round(100 * read_size / total_size))
                        system.LogPercentComplete(percent_done)
                return "%x" % checksum
        return ""
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate crc32 for %s" % src)
            system.LogErrorAndQuit(e)
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
            system.LogInfo("Calculating md5 for %s" % src)
        if not pretend_run:
            import hashlib
            with open(src, "rb") as file:
                read_size = 0
                total_size = os.path.getsize(src)
                percent_done = 0
                md5_hash = hashlib.md5()
                if verbose:
                    system.LogPercentComplete(percent_done)
                for chunk in iter(lambda: file.read(chunksize),b""):
                    md5_hash.update(chunk)
                    if verbose:
                        read_size += len(chunk)
                        percent_done = int(round(100 * read_size / total_size))
                        system.LogPercentComplete(percent_done)
                return md5_hash.hexdigest()
        return ""
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate md5 for %s" % src)
            system.LogErrorAndQuit(e)
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
            system.LogInfo("Calculating sha1 for %s" % src)
        if not pretend_run:
            import hashlib
            with open(src, "rb") as file:
                read_size = 0
                total_size = os.path.getsize(src)
                percent_done = 0
                sha1_hash = hashlib.sha1()
                if verbose:
                    system.LogPercentComplete(percent_done)
                for chunk in iter(lambda: file.read(chunksize),b""):
                    sha1_hash.update(chunk)
                    if verbose:
                        read_size += len(chunk)
                        percent_done = int(round(100 * read_size / total_size))
                        system.LogPercentComplete(percent_done)
                return sha1_hash.hexdigest()
        return ""
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate sha1 for %s" % src)
            system.LogErrorAndQuit(e)
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
            system.LogInfo("Calculating sha256 for %s" % src)
        if not pretend_run:
            import hashlib
            with open(src, "rb") as file:
                read_size = 0
                total_size = os.path.getsize(src)
                percent_done = 0
                sha256_hash = hashlib.sha256()
                if verbose:
                    system.LogPercentComplete(percent_done)
                for chunk in iter(lambda: file.read(chunksize),b""):
                    sha256_hash.update(chunk)
                    if verbose:
                        read_size += len(chunk)
                        percent_done = int(round(100 * read_size / total_size))
                        system.LogPercentComplete(percent_done)
                return sha256_hash.hexdigest()
        return ""
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate sha256 for %s" % src)
            system.LogErrorAndQuit(e)
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
            system.LogInfo("Calculating xxh3 for %s" % src)
        if not pretend_run:
            import xxhash
            with open(src, "rb") as file:
                read_size = 0
                total_size = os.path.getsize(src)
                percent_done = 0
                xxh3_hash = xxhash.xxh3_64()
                if verbose:
                    system.LogPercentComplete(percent_done)
                for chunk in iter(lambda: file.read(chunksize),b""):
                    xxh3_hash.update(chunk)
                    if verbose:
                        read_size += len(chunk)
                        percent_done = int(round(100 * read_size / total_size))
                        system.LogPercentComplete(percent_done)
                return xxh3_hash.hexdigest()
        return ""
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate xxh3 for %s" % src)
            system.LogErrorAndQuit(e)
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
    for obj in system.GetDirectoryContents(directory):
        obj_path = system.JoinPaths(directory, obj)
        if system.IsPathFile(obj_path):
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
    for obj in system.GetDirectoryContents(directory):
        obj_path = system.JoinPaths(directory, obj)
        if system.IsPathFile(obj_path):
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
    first_exists = system.DoesPathExist(first, case_sensitive_paths = case_sensitive_paths)
    second_exists = system.DoesPathExist(second, case_sensitive_paths = case_sensitive_paths)
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
        first_checksums = sorted(archive.GetArchiveChecksums(first))
        second_checksums = sorted(archive.GetArchiveChecksums(second))
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

###########################################################

# Read hash file
def ReadHashFile(
    src,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    json_hashes = system.ReadJsonFile(
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
            file_location = system.JoinPaths(json_hash["dir"], json_hash["filename"])
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
    success = system.WriteJsonFile(
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
        system.LogInfo("Sorting hash file %s" % src)
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
    input_file_fullpath = system.JoinPaths(base_path, src)
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
    path_file = system.GetFilenameFile(src)
    path_dir = system.GetFilenameDirectory(src)
    path_full = system.JoinPaths(base_path, path_dir, path_file)
    system.LogInfo("Hashing file %s ..." % path_full)

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
    base_path,
    output_file,
    passphrase = None,
    checked_base_path = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get hash contents
    hash_contents = {}
    if system.IsPathFile(output_file):
        hash_contents = ReadHashFile(
            src = output_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Hash each file in the input path
    for file in system.BuildFileList(src):
        if os.path.realpath(file) == os.path.realpath(output_file):
            continue

        # Split by base path
        file_parts = system.SplitFilePath(file, base_path)
        if len(file_parts) != 2:
            continue

        # Check if file needs to be hashed
        relative_base = file_parts[0]
        relative_file = system.JoinPaths(base_path, file_parts[1])
        if DoesFileNeedToBeHashed(relative_file, relative_base, hash_contents):

            # Calculate hash
            hash_data = CalculateHash(
                filename = relative_file,
                base_path = relative_base,
                passphrase = passphrase,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            hash_entry_key = system.JoinPaths(hash_data["dir"], hash_data["filename"])

            # Merge hash
            if hash_entry_key in hash_contents:
                different_hash = hash_contents[hash_entry_key]["hash"] == hash_data["hash"]
                different_size = int(hash_contents[hash_entry_key]["size"]) == int(hash_data["size"])
                different_hash_enc = hash_contents[hash_entry_key]["hash_enc"] == hash_data["hash_enc"]
                different_size_enc = int(hash_contents[hash_entry_key]["size_enc"]) == int(hash_data["size_enc"])
                if different_hash or different_size or different_hash_enc or different_size_enc:
                    hash_contents[hash_entry_key] = system.MergeDictionaries(
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

    # Remove keys regarding files that do not exist
    if system.DoesPathExist(checked_base_path):
        for hash_key in sorted(hash_contents.keys()):
            hashed_file = system.JoinPaths(checked_base_path, hash_key)
            if not os.path.exists(hashed_file):
                del hash_contents[hash_key]

    # Write hash file
    return WriteHashFile(
        src = output_file,
        hash_contents = hash_contents,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################

# Hash category files
def HashCategoryFiles(
    src,
    game_supercategory,
    game_category,
    game_subcategory,
    passphrase = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check required types
    system.AssertIsNotNone(game_supercategory, "game_supercategory")
    system.AssertIsNotNone(game_category, "game_category")
    system.AssertIsNotNone(game_subcategory, "game_subcategory")

    # Check input path
    if not os.path.exists(src):
        return False

    # Get hash file
    hash_file = environment.GetHashesMetadataFile(game_supercategory, game_category, game_subcategory)

    # Make directories/files
    system.MakeDirectory(
        dir = system.GetFilenameDirectory(hash_file),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    system.TouchFile(
        src = hash_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Hash files
    success = HashFiles(
        src = src,
        base_path = system.JoinPaths(game_supercategory, game_category, game_subcategory),
        output_file = hash_file,
        passphrase = passphrase,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return success

###########################################################
