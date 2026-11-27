# Checking and editing text files in place: headers, string replacements,
# appended lines and sorted contents.

# Imports
import os
import re

# Local imports
from joybox import logger
from joybox import fileops
from joybox import serialization

###########################################################
# File checking utilities
###########################################################

# Determine if file is correctly headered
def is_file_correctly_headered(src, expected_header):
    if not os.path.isfile(src):
        return False
    if isinstance(expected_header, str):
        expected_header = bytes(expected_header, "utf-8")
    elif not isinstance(expected_header, bytes):
        return False
    return serialization.read_binary_file(src, length = len(expected_header)) == expected_header

###########################################################
# File content modification utilities
###########################################################

# The line breaks Python's universal newlines read a text file by
universal_newline_pattern = re.compile(r"\r\n|\r|\n")

# Apply string replacements to contents, skipping any without both a from and a to
def apply_replacements(contents, replacements):
    for entry in replacements:
        if entry["from"] and entry["to"]:
            contents = contents.replace(entry["from"], entry["to"])
    return contents

# Replace strings in file
def replace_strings_in_file(src, replacements = (), verbose = False, pretend_run = False, exit_on_failure = False):
    if not os.path.isfile(src):
        if verbose:
            logger.log_info("Path %s is not a file" % src)
        return False
    if verbose:
        logger.log_info("Replacing lines in file %s" % src)
    if pretend_run:
        return True
    src_contents = serialization.read_text_file(src, exit_on_failure = exit_on_failure)
    if src_contents is None:
        return False
    try:
        new_contents = apply_replacements(src_contents, replacements)
    except KeyError as e:
        return fileops.report_failure("Unable to replace strings in file %s, a replacement lacks %s" % (src, e), e, exit_on_failure)
    return serialization.write_text_file(src, new_contents, exit_on_failure = exit_on_failure)

# Append line to file
def append_line_to_file(src, line, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                logger.log_info("Path %s is not a file" % src)
            return False
        if verbose:
            logger.log_info("Adding line '%s' to file %s" % (line, src))
        if not pretend_run:
            # Appended as bytes, so the file keeps its own line endings
            src_bytes = serialization.read_binary_file(src, exit_on_failure = exit_on_failure)
            if src_bytes is None:
                return False
            src_lines = universal_newline_pattern.split(src_bytes.decode("utf-8"))
            if line in src_lines[:-1] or (src_lines[-1] and src_lines[-1] == line):
                return True
            separator = b"" if not src_bytes or src_bytes.endswith((b"\n", b"\r")) else b"\n"
            return serialization.write_binary_file(
                src, src_bytes + separator + (line + "\n").encode("utf-8"), exit_on_failure = exit_on_failure)
        return True
    except UnicodeDecodeError as e:
        return fileops.report_failure("Unable to add line '%s' to file %s" % (line, src), e, exit_on_failure)

# Sort file contents
def sort_file_contents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    if not os.path.isfile(src):
        if verbose:
            logger.log_info("Path %s is not a file" % src)
        return False
    if verbose:
        logger.log_info("Sorting contents of file %s" % src)
    if pretend_run:
        return True
    src_contents = serialization.read_text_file(src, exit_on_failure = exit_on_failure)
    if src_contents is None:
        return False
    return serialization.write_text_file(
        src, "".join(line + "\n" for line in sorted(src_contents.splitlines())), exit_on_failure = exit_on_failure)
