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
def CalculateFileCRC32(filename, chunksize = config.hash_chunk_size, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Calculating crc32 for %s" % filename)
        import zlib
        with open(filename, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(filename)
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
            system.LogError("Unable to calculate crc32 for %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return ""

# Calculate file md5
def CalculateFileMD5(filename, chunksize = config.hash_chunk_size, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Calculating md5 for %s" % filename)
        import hashlib
        with open(filename, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(filename)
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
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate md5 for %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return ""

# Calculate file sha1
def CalculateFileSHA1(filename, chunksize = config.hash_chunk_size, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Calculating sha1 for %s" % filename)
        import hashlib
        with open(filename, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(filename)
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
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate sha1 for %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return ""

# Calculate file sha256
def CalculateFileSHA256(filename, chunksize = config.hash_chunk_size, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Calculating sha256 for %s" % filename)
        import hashlib
        with open(filename, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(filename)
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
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate sha256 for %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return ""

# Calculate file xxh3
def CalculateFileXXH3(filename, chunksize = config.hash_chunk_size, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Calculating xxh3 for %s" % filename)
        import xxhash
        with open(filename, "rb") as file:
            read_size = 0
            total_size = os.path.getsize(filename)
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
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to calculate xxh3 for %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return ""

###########################################################

# Check if files are identical
def AreFilesIdentical(first, second, case_sensitive_paths = True, verbose = False, exit_on_failure = False):
    first_exists = system.DoesPathExist(first, case_sensitive_paths = case_sensitive_paths)
    second_exists = system.DoesPathExist(second, case_sensitive_paths = case_sensitive_paths)
    if first_exists and second_exists:
        first_crc32 = CalculateFileCRC32(first, verbose = verbose, exit_on_failure = exit_on_failure)
        second_crc32 = CalculateFileCRC32(second, verbose = verbose, exit_on_failure = exit_on_failure)
        return first_crc32 == second_crc32
    return False

# Find duplicate files in the search directory
def FindDuplicateFiles(filename, directory, verbose = False, exit_on_failure = False):
    found_files = []
    test_checksum = CalculateFileCRC32(filename, verbose = verbose, exit_on_failure = exit_on_failure)
    for obj in system.GetDirectoryContents(directory):
        obj_path = os.path.join(directory, obj)
        if os.path.isfile(obj_path):
            obj_checksum = CalculateFileCRC32(obj_path, verbose = verbose, exit_on_failure = exit_on_failure)
            if test_checksum == obj_checksum:
                found_files.append(obj_path)
    return found_files

# Find duplicate archives in the search directory
def FindDuplicateArchives(filename, directory, verbose = False, exit_on_failure = False):
    found_files = []
    test_checksums = archive.GetArchiveChecksums(filename)
    for obj in system.GetDirectoryContents(directory):
        obj_path = os.path.join(directory, obj)
        if os.path.isfile(obj_path):
            obj_checksums = archive.GetArchiveChecksums(obj_path)
            if [i for i in test_checksums if i not in obj_checksums] == []:
                found_files.append(obj_path)
    return found_files

###########################################################

# Read hash file
def ReadHashFile(filename, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Reading hash file %s" % filename)
        hash_contents = {}
        with open(filename, "r", encoding="utf8") as f:
            for line in f.readlines():
                tokens = line.strip().split(" || ")
                if len(tokens) >= 4:
                    file_location = tokens[0]
                    file_hash = tokens[1]
                    file_size = tokens[2]
                    file_mtime = tokens[3]
                    file_entry = {}
                    file_entry["filename"] = file_location
                    file_entry["hash"] = file_hash
                    file_entry["size"] = file_size
                    file_entry["mtime"] = file_mtime
                    hash_contents[file_location] = file_entry
        return hash_contents
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to read hash file %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return {}

# Write hash file
def WriteHashFile(filename, hash_contents, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Writing hash file %s" % filename)
        with open(filename, "w", encoding="utf8") as f:
            for hash_key in sorted(hash_contents.keys()):
                hash_data = hash_contents[hash_key]
                hash_replacements = (
                    hash_data["filename"],
                    hash_data["hash"],
                    hash_data["size"],
                    hash_data["mtime"])
                f.write("%s || %s || %s || %s\n" % hash_replacements)
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to write hash file %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return False

# Append hash file
def AppendHashFile(filename, hash_data, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            system.Log("Appending hash file %s" % filename)
        with open(filename, "a", encoding="utf8") as f:
            hash_replacements = (
                hash_data["filename"],
                hash_data["hash"],
                hash_data["size"],
                hash_data["mtime"])
            f.write("%s || %s || %s || %s\n" % hash_replacements)
        return True
    except Exception as e:
        if exit_on_failure:
            system.LogError("Unable to append hash file %s" % filename)
            system.LogError(e)
            sys.exit(1)
        return False

# Sort hash file
def SortHashFile(filename, verbose = False, exit_on_failure = False):
    if verbose:
        system.Log("Sorting hash file %s" % filename)
    hash_contents = ReadHashFile(
        filename = filename,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return WriteHashFile(
        filename = filename,
        hash_contents = hash_contents,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

# Check if file needs to be hashed
def DoesFileNeedToBeHashed(input_file, base_path, hash_contents = {}):
    if input_file not in hash_contents.keys():
        return True
    input_file_fullpath = os.path.join(base_path, input_file)
    input_file_size = str(os.path.getsize(input_file_fullpath))
    input_file_mtime = str(int(os.path.getmtime(input_file_fullpath)))
    if input_file_size != hash_contents[input_file]["size"]:
        return True
    if input_file_mtime != hash_contents[input_file]["mtime"]:
        return True
    return False

###########################################################

# Calculate hash
def CalculateHash(filename, base_path, passphrase = None, verbose = False, exit_on_failure = False):

    # Get full path of file
    fullpath = os.path.join(base_path, filename)
    system.Log("Hashing file %s ..." % fullpath)

    # Create hash data
    hash_data = {}
    if cryption.IsFileEncrypted(fullpath):
        file_info = cryption.GetEmbeddedFileInfo(
            source_file = fullpath,
            passphrase = passphrase,
            hasher = CalculateFileXXH3,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        if file_info:
            hash_data["filename"] = os.path.join(system.GetFilenameDirectory(filename), file_info["filename"])
            hash_data["hash"] = file_info["hash"]
            hash_data["size"] = file_info["size"]
            hash_data["mtime"] = file_info["mtime"]
    else:
        hash_data["filename"] = filename
        hash_data["hash"] = CalculateFileXXH3(fullpath, verbose = verbose, exit_on_failure = exit_on_failure)
        hash_data["size"] = os.path.getsize(fullpath)
        hash_data["mtime"] = int(os.path.getmtime(fullpath))

    # Return hash data
    return hash_data

# Hash files
def HashFiles(input_path, base_path, output_file, passphrase = None, verbose = False, exit_on_failure = False):

    # Get hash contents
    hash_contents = {}
    if os.path.isfile(output_file):
        hash_contents = ReadHashFile(output_file, verbose = verbose, exit_on_failure = exit_on_failure)

    # Hash each file in the input path
    for file in system.BuildFileList(input_path):
        if os.path.realpath(file) == os.path.realpath(output_file):
            continue

        # Check if file needs to be hashed
        relative_file = system.RebaseFilePath(file, input_path, base_path)
        relative_base = file.replace(relative_file, "")
        if DoesFileNeedToBeHashed(relative_file, relative_base, hash_contents):

            # Calculate hash
            hash_data = CalculateHash(
                filename = relative_file,
                base_path = relative_base,
                passphrase = passphrase,
                verbose = verbose,
                exit_on_failure = exit_on_failure)
            hash_contents[hash_data["filename"]] = hash_data

            # Append hash
            success = AppendHashFile(
                filename = output_file,
                hash_data = hash_data,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

    # Remove keys regarding files that do not exist
    for hash_key in sorted(hash_contents.keys()):
        hashed_file_base = environment.GetLockerGamingRootDir()
        hashed_file_offset = hash_contents[hash_key]["filename"]
        hashed_file = os.path.join(hashed_file_base, hashed_file_offset)
        if not os.path.exists(hashed_file):
            del hash_contents[hash_key]

    # Write hash file
    return WriteHashFile(
        filename = output_file,
        hash_contents = hash_contents,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

###########################################################

# Hash category files
def HashCategoryFiles(input_path, file_supercategory, file_category, file_subcategory, passphrase = None, verbose = False, exit_on_failure = False):

    # Check required types
    system.AssertIsString(file_supercategory, "file_supercategory")
    system.AssertIsString(file_category, "file_category")
    system.AssertIsString(file_subcategory, "file_subcategory")

    # Check input path
    if not os.path.exists(input_path):
        return False

    # Get hash file
    hash_file = environment.GetHashesMetadataFile(file_supercategory, file_category, file_subcategory)

    # Make directories/files
    system.MakeDirectory(
        dir = system.GetFilenameDirectory(hash_file),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    system.TouchFile(
        src = hash_file,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Hash files
    success = HashFiles(
        input_path = input_path,
        base_path = os.path.join(file_supercategory, file_category, file_subcategory),
        output_file = hash_file,
        passphrase = passphrase,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        system.LogError("Unable to hash files from %s" % input_path)
        return False

    # Sort hash file
    return SortHashFile(hash_file, verbose = verbose, exit_on_failure = exit_on_failure)

###########################################################
