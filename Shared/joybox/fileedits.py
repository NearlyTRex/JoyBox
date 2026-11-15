# Checking and editing text files in place: headers, string replacements,
# appended lines and sorted contents.

# Imports
import os
import re

# Local imports
from joybox import logger
from joybox import runtime
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

# Replace strings in file
def replace_strings_in_file(src, replacements = (), verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                logger.log_info("Path %s is not a file" % src)
            return False
        if verbose:
            logger.log_info("Replacing lines in file %s" % src)
        if not pretend_run:
            src_contents = serialization.read_text_file(src, exit_on_failure = exit_on_failure)
            if src_contents is None:
                return False
            for entry in replacements:
                entry_from = entry["from"]
                entry_to = entry["to"]
                if entry_from and entry_to:
                    src_contents = src_contents.replace(entry_from, entry_to)
            return serialization.write_text_file(src, src_contents, exit_on_failure = exit_on_failure)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to replace strings in file %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

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
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to add line '%s' to file %s" % (line, src))
            logger.log_error(e)
            runtime.quit_program()
        return False

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
