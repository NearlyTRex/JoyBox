# Imports
import os, os.path
import sys

# Local imports
import config
import environment
import system
import archive

# Check if files are identical
def AreFilesIdentical(first, second, case_sensitive_paths = True):
    first_exists = system.DoesPathExist(first, case_sensitive_paths = case_sensitive_paths)
    second_exists = system.DoesPathExist(second, case_sensitive_paths = case_sensitive_paths)
    if first_exists and second_exists:
        first_crc32 = CalculateFileCRC32(first)
        second_crc32 = CalculateFileCRC32(second)
        return first_crc32 == second_crc32
    return False

# Find duplicate files in the search directory
def FindDuplicateFiles(filename, directory):
    found_files = []
    test_checksum = CalculateFileCRC32(filename)
    for obj in system.GetDirectoryContents(directory):
        obj_path = os.path.join(directory, obj)
        if os.path.isfile(obj_path):
            obj_checksum = CalculateFileCRC32(obj_path)
            if test_checksum == obj_checksum:
                found_files.append(obj_path)
    return found_files

# Find duplicate archives in the search directory
def FindDuplicateArchives(filename, directory):
    found_files = []
    test_checksums = archive.GetArchiveChecksums(filename)
    for obj in system.GetDirectoryContents(directory):
        obj_path = os.path.join(directory, obj)
        if os.path.isfile(obj_path):
            obj_checksums = archive.GetArchiveChecksums(obj_path)
            if [i for i in test_checksums if i not in obj_checksums] == []:
                found_files.append(obj_path)
    return found_files

# Calculate string crc32
def CalculateStringCRC32(string):
    import zlib
    return "%x" % zlib.crc32(chunk, checksum)

# Calculate string md5
def CalculateStringMD5(string):
    import hashlib
    return hashlib.md5(string).hexdigest()

# Calculate string sha1
def CalculateStringSHA1(string):
    import hashlib
    return hashlib.sha1(string).hexdigest()

# Calculate string sha256
def CalculateStringSHA256(string):
    import hashlib
    return hashlib.sha256(string).hexdigest()

# Calculate string XXH3
def CalculateStringXXH3(string):
    import xxhash
    return xxhash.xxh3_64(string).hexdigest()

# Calculate file crc32
def CalculateFileCRC32(filename, chunksize = config.hash_chunk_size):
    import zlib
    with open(filename, "rb") as file:
        checksum = 0
        while (chunk := file.read(chunksize)):
            checksum = zlib.crc32(chunk, checksum)
        return "%x" % checksum

# Calculate file md5
def CalculateFileMD5(filename, chunksize = config.hash_chunk_size):
    import hashlib
    with open(filename, "rb") as file:
        md5_hash = hashlib.md5()
        for chunk in iter(lambda: file.read(chunksize),b""):
            md5_hash.update(chunk)
        return md5_hash.hexdigest()

# Calculate file sha1
def CalculateFileSHA1(filename, chunksize = config.hash_chunk_size):
    import hashlib
    with open(filename, "rb") as file:
        sha1_hash = hashlib.sha1()
        for chunk in iter(lambda: file.read(chunksize),b""):
            sha1_hash.update(chunk)
        return sha1_hash.hexdigest()

# Calculate file sha256
def CalculateFileSHA256(filename, chunksize = config.hash_chunk_size):
    import hashlib
    with open(filename, "rb") as file:
        sha256_hash = hashlib.sha256()
        for chunk in iter(lambda: file.read(chunksize),b""):
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

# Calculate file xxh3
def CalculateFileXXH3(filename, chunksize = config.hash_chunk_size):
    import xxhash
    with open(filename, "rb") as file:
        xxh3_hash = xxhash.xxh3_64()
        for chunk in iter(lambda: file.read(chunksize),b""):
            xxh3_hash.update(chunk)
        return xxh3_hash.hexdigest()

# Calculate hash
def CalculateHash(filename, original_base_path, new_base_path):
    print("Hashing file %s ..." % filename)
    hash_data = {}
    hash_data["location"] = system.RebaseFilePath(filename, original_base_path, new_base_path)
    hash_data["hash"] = CalculateFileXXH3(filename)
    hash_data["size"] = os.path.getsize(filename)
    return hash_data

# Read hash file
def ReadHashFile(filename):
    hash_contents = {}
    with open(filename, "r", encoding="utf8") as f:
        for line in f.readlines():
            tokens = line.strip().split(" || ")
            if len(tokens) >= 3:
                file_location = tokens[0]
                file_hash = tokens[1]
                file_size = tokens[2]
                file_entry = {}
                file_entry["hash"] = file_hash
                file_entry["size"] = file_size
                hash_contents[file_location] = file_entry
    return hash_contents

# Write hash file
def WriteHashFile(filename, hash_contents):
    with open(filename, "w", encoding="utf8") as f:
        for hash_key in sorted(hash_contents.keys()):
            hash_data = hash_contents[hash_key]
            f.write("%s || %s || %s\n" % (hash_key, hash_data["hash"], hash_data["size"]))

# Sort hash file
def SortHashFile(filename):
    hash_contents = ReadHashFile(filename)
    WriteHashFile(filename, hash_contents)

# Hash all files
def HashAllFiles(input_path, base_path, output_file):

    # Start writing whole file
    with open(output_file, "w", encoding="utf8") as f:
        for file in system.BuildFileList(input_path):

            # Hash each file
            current_file = file
            if os.path.realpath(current_file) == os.path.realpath(output_file):
                continue
            hash_data = CalculateHash(
                filename = current_file,
                original_base_path = input_path,
                new_base_path = base_path)
            f.write("%s || %s || %s\n" % (hash_data["location"], hash_data["hash"], hash_data["size"]))

# Hash new files
def HashNewFiles(input_path, base_path, output_file):

    # Read existing hash file
    hash_contents = {}
    if os.path.exists(output_file):
        hash_contents = ReadHashFile(output_file)

    # Check for new files
    new_files = []
    for file in system.BuildFileList(input_path):
        rebased_file = system.RebaseFilePath(file, input_path, base_path)
        if not rebased_file in hash_contents.keys():
            new_files.append(file)

    # For each new file, add the new hash data
    for new_file in sorted(new_files):
        hash_data = CalculateHash(
            filename = new_file,
            original_base_path = input_path,
            new_base_path = base_path)
        hash_contents[hash_data["location"]] = hash_data

    # Write updated hash file
    WriteHashFile(output_file, hash_contents)

# Hash custom files
def HashCustomFiles(input_path, disc_name, file_supercategory, file_category, file_subcategory, all_files = True):

    # Check required types
    system.AssertIsString(input_path, "input_path")
    system.AssertIsString(file_supercategory, "file_supercategory")
    system.AssertIsString(file_category, "file_category")
    if disc_name:
        system.AssertIsString(disc_name, "disc_name")
    else:
        system.AssertIsString(file_subcategory, "file_subcategory")

    # Get hash file
    hash_file = ""
    if disc_name:
        hash_file = os.path.join(environment.GetDiscMetadataHashesDir(), file_supercategory, disc_name + ".txt")
    else:
        hash_file = os.path.join(environment.GetMainMetadataHashesDir(), file_supercategory, file_category, file_subcategory + ".txt")

    # Make directories/files
    system.MakeDirectory(
        dir = system.GetFilenameDirectory(hash_file),
        verbose = True,
        exit_on_failure = True)
    system.TouchFile(
        src = hash_file,
        verbose = True,
        exit_on_failure = True)

    # Hash files
    if all_files:
        HashAllFiles(
            input_path = input_path,
            base_path = file_supercategory + "/" + file_category + "/" + file_subcategory,
            output_file = hash_file)
    else:
        HashNewFiles(
            input_path = input_path,
            base_path = file_supercategory + "/" + file_category + "/" + file_subcategory,
            output_file = hash_file)

    # Sort hash file
    SortHashFile(hash_file)

# Hash standard files
def HashStandardFiles(input_path, file_supercategory, file_category, file_subcategory, all_files = True):

    # Check required types
    system.AssertIsString(input_path, "input_path")
    system.AssertIsString(file_supercategory, "file_supercategory")
    system.AssertIsString(file_category, "file_category")
    system.AssertIsString(file_subcategory, "file_subcategory")

    # Ignore non-existent or empty input paths
    if not os.path.exists(input_path) or system.IsDirectoryEmpty(input_path):
        return

    # Get hash file
    hash_file = os.path.join(environment.GetMainMetadataHashesDir(), file_supercategory, file_category, file_subcategory + ".txt")

    # Make directories/files
    system.MakeDirectory(
        dir = system.GetFilenameDirectory(hash_file),
        verbose = True,
        exit_on_failure = True)
    system.TouchFile(
        src = hash_file,
        verbose = True,
        exit_on_failure = True)

    # Hash files
    if all_files:
        HashAllFiles(
            input_path = input_path,
            base_path = file_supercategory + "/" + file_category + "/" + file_subcategory,
            output_file = hash_file)
    else:
        HashNewFiles(
            input_path = input_path,
            base_path = file_supercategory + "/" + file_category + "/" + file_subcategory,
            output_file = hash_file)

    # Sort hash file
    SortHashFile(hash_file)
