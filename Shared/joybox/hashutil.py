# Imports
import zlib
import hashlib

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
