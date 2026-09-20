# Imports
import hashlib
import os
import zlib

# Local imports
from joybox import hashing


# Write a file and return its path
def write_file(directory, name, contents = b"payload"):
    path = os.path.join(str(directory), name)
    os.makedirs(os.path.dirname(path), exist_ok = True)
    with open(path, "wb") as handle:
        handle.write(contents)
    return path


# The digests the module should produce for a blob, computed independently
def expected_digests(contents):
    return {
        "crc32": "%08x" % zlib.crc32(contents, 0),
        "md5": hashlib.md5(contents).hexdigest(),
        "sha1": hashlib.sha1(contents).hexdigest(),
        "sha256": hashlib.sha256(contents).hexdigest(),
    }


# One manifest entry in the full (encrypted-aware) shape
def entry(directory, filename, hash_value = "abc", size = 4, mtime = 100):
    return {
        "dir": directory,
        "filename": filename,
        "hash": hash_value,
        "size": size,
        "mtime": mtime,
        "filename_enc": "",
        "hash_enc": "",
        "size_enc": 0,
    }


# A manifest keyed the way the module keys it
def manifest(*entries):
    contents = {}
    for data in entries:
        key = "/".join(part for part in [data["dir"], data["filename"]] if part)
        contents[key] = data
    return contents
