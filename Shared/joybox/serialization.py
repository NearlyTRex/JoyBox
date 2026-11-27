# Imports
import importlib
import os
import json
import csv
import tomllib

# Local imports
from joybox import logger
from joybox import paths
from joybox import datautils
from joybox import runtime

# Get yaml, imported on first use
def _get_yaml():
    return importlib.import_module("yaml")

###########################################################
# Text file I/O utilities
###########################################################

# Read text file
def read_text_file(src, encoding = "utf-8", errors = "strict", verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading %s" % src)
        with open(src, "r", encoding = encoding, errors = errors) as input_file:
            return input_file.read()
    except (OSError, ValueError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return None

# Read a text file as its lines, split only at newlines and without them, or None
# when it cannot be read
def read_text_lines(src, encoding = "utf-8", errors = "strict", verbose = False, exit_on_failure = False):
    contents = read_text_file(src, encoding = encoding, errors = errors, verbose = verbose, exit_on_failure = exit_on_failure)
    if contents is None:
        return None
    lines = contents.split("\n")
    return lines[:-1] if lines[-1] == "" else lines

# Read binary file
def read_binary_file(src, offset = 0, length = None, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading %s" % src)
        with open(src, "rb") as input_file:
            input_file.seek(offset)
            if length is None:
                return input_file.read()
            return input_file.read(length)
    except OSError as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return None

# Read a binary file a chunk at a time; an error is raised to the caller, which has
# already used the chunks before it
def read_binary_chunks(src, chunk_size = 1024 * 1024):
    with open(src, "rb") as input_file:
        yield from iter(lambda: input_file.read(chunk_size), b"")

# Write bytes to a file, False when it cannot be written
def write_binary_file(src, contents, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing %s" % src)
        if not pretend_run:
            with open(src, "wb") as output_file:
                output_file.write(contents)
        return True
    except (OSError, TypeError) as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

# Copy length bytes, starting at offset, out of one binary file into another
def copy_binary_range(src, dest, offset, length, chunk_size = 1024 * 1024, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Copying %d bytes at %d from %s to %s" % (length, offset, src, dest))
        if pretend_run:
            return True
        with open(src, "rb") as input_file, open(dest, "wb") as output_file:
            input_file.seek(offset)
            remaining = length
            while remaining > 0:
                chunk = input_file.read(min(remaining, chunk_size))
                if not chunk:
                    raise EOFError("%s ends %d bytes short" % (src, remaining))
                output_file.write(chunk)
                remaining -= len(chunk)
        return True
    except (OSError, EOFError) as e:
        if exit_on_failure:
            logger.log_error("Unable to copy from %s to %s" % (src, dest))
            logger.log_error(e)
            runtime.quit_program()
        return False

# Read records from an open binary file, keeping the first keep_size bytes of each
def read_binary_records(input_file, record_count, record_size, keep_size):
    chunk = input_file.read(record_count * record_size)
    if len(chunk) != record_count * record_size:
        raise EOFError("file ends %d records short" % (record_count - len(chunk) // record_size))
    if keep_size == record_size:
        return chunk
    view = memoryview(chunk)
    return b"".join(view[start:start + keep_size] for start in range(0, len(chunk), record_size))

# Copy fixed-size records out of a binary file, keeping the first keep_size bytes of each
def copy_binary_records(
    src,
    dest,
    offset,
    record_count,
    record_size,
    keep_size = None,
    records_per_read = 1024,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Copying %d records of %d bytes from %s to %s" % (record_count, record_size, src, dest))
        if pretend_run:
            return True
        with open(src, "rb") as input_file, open(dest, "wb") as output_file:
            input_file.seek(offset)
            for first in range(0, record_count, records_per_read):
                count = min(records_per_read, record_count - first)
                output_file.write(read_binary_records(input_file, count, record_size, keep_size or record_size))
        return True
    except (OSError, ValueError, EOFError) as e:
        if exit_on_failure:
            logger.log_error("Unable to copy records from %s to %s" % (src, dest))
            logger.log_error(e)
            runtime.quit_program()
        return False

# Write text file
def write_text_file(src, contents, encoding = "utf-8", newline = "\n", verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing %s" % src)
        if not pretend_run:
            parent_dir = os.path.dirname(src)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            with open(src, "w", encoding = encoding, newline = newline) as output_file:
                output_file.write(contents)
        return True
    except (OSError, ValueError) as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

###########################################################
# JSON file I/O utilities
###########################################################

# Parse json string
def parse_json_string(string, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Parsing %s" % string)
        json_data = json.loads(string)
        return json_data
    except (ValueError, TypeError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % string)
            logger.log_error(e)
            runtime.quit_program()
        return {}

# Parse a json string, or None when it is not json, for a caller that must tell
# a failure from an empty object
def parse_json_or_none(string):
    try:
        return json.loads(string)
    except (TypeError, ValueError):
        return None

# Read json file
def read_json_file(src, verbose = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return {}
        if verbose:
            logger.log_info("Reading %s" % src)
        json_data = {}
        with open(src, "r", encoding = "utf-8") as input_file:
            file_contents = input_file.read()
            json_data = json.loads(file_contents)
        return json_data
    except (OSError, ValueError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return {}

# Write json file
def write_json_file(src, json_data, sort_keys = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            logger.log_info("Writing %s" % src)
        if not pretend_run:
            parent_dir = os.path.dirname(src)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            with open(src, "w", newline='\n', encoding = "utf-8") as output_file:
                json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                output_file.write(json_string)
        return True
    except (OSError, ValueError, TypeError) as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

# Clean json file
def clean_json_file(src, sort_keys = False, remove_empty_values = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            logger.log_info("Cleaning %s" % src)
        if not pretend_run:
            json_data = None
            with open(src, "r", encoding = "utf-8") as input_file:
                json_data = json.loads(input_file.read())
                if remove_empty_values:
                    json_keys_to_remove = []
                    for key in json_data.keys():
                        json_value = json_data[key]
                        if json_value is None:
                            json_keys_to_remove.append(key)
                        if isinstance(json_value, str) and len(json_value) == 0:
                            json_keys_to_remove.append(key)
                        if isinstance(json_value, dict) and len(json_value.keys()) == 0:
                            json_keys_to_remove.append(key)
                        if isinstance(json_value, list) and len(json_value) == 0:
                            json_keys_to_remove.append(key)
                        if json_value is False:
                            json_keys_to_remove.append(key)
                    for key in json_keys_to_remove:
                        json_data.pop(key)
            if json_data is not None:
                with open(src, "w", newline='\n', encoding = "utf-8") as output_file:
                    json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                    output_file.write(json_string)
        return True
    except (OSError, ValueError, TypeError) as e:
        if exit_on_failure:
            logger.log_error("Unable to clean %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

# Search json files
def search_json_files(src, search_values = (), search_keys = None, verbose = False, exit_on_failure = False):
    found_files = []
    for json_file in paths.build_file_list_by_extensions(src, extensions = [".json"]):
        json_data = read_json_file(
            src = json_file,
            verbose = verbose,
            exit_on_failure = exit_on_failure)
        for search_value in search_values:
            if search_value:
                json_matches = datautils.search_dictionary(
                    data = json_data,
                    search_value = search_value,
                    search_keys = search_keys)
                if len(json_matches):
                    found_files.append(json_file)
    return found_files

###########################################################
# YAML file I/O utilities
###########################################################

# Read yaml file
def read_yaml_file(src, verbose = False, exit_on_failure = False):
    yaml = _get_yaml()
    try:
        if not src.endswith(".yaml"):
            return {}
        if verbose:
            logger.log_info("Reading %s" % src)
        yaml_data = {}
        with open(src, "r", encoding = "utf-8") as input_file:
            file_contents = input_file.read()
            file_contents = file_contents.replace(u'\x81', "")
            file_contents = file_contents.replace(u'\x82', "")
            yaml_data = yaml.safe_load(file_contents)
        return yaml_data
    except (OSError, yaml.YAMLError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return {}

###########################################################
# CSV file I/O utilities
###########################################################

# Read csv file
def read_csv_file(src, headers, verbose = False, exit_on_failure = False):
    try:
        if not src.endswith(".csv"):
            return []
        if verbose:
            logger.log_info("Reading %s" % src)
        csv_data = []
        with open(src, mode="r", newline="", encoding="utf-8") as input_file:
            csv_reader = csv.reader(input_file)
            for row in csv_reader:
                if len(row) == len(headers):
                    row = [field.strip('"') for field in row]
                    row_dict = {headers[i]: row[i] for i in range(len(headers))}
                    csv_data.append(row_dict)
        return csv_data
    except (OSError, ValueError, csv.Error) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return []

# Read a csv file whose first row names its columns, as one dict per row, or None
# when it cannot be read
def read_csv_records(src, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading %s" % src)
        with open(src, mode = "r", newline = "", encoding = "utf-8") as input_file:
            return list(csv.DictReader(input_file))
    except (OSError, UnicodeDecodeError, csv.Error) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return None

# Write one csv row per record, under a row naming the columns
def write_csv_records(src, columns, records, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing %s" % src)
        if not pretend_run:
            with open(src, mode = "w", newline = "", encoding = "utf-8") as output_file:
                writer = csv.DictWriter(output_file, fieldnames = columns)
                writer.writeheader()
                writer.writerows(records)
        return True
    except (OSError, ValueError, csv.Error) as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return False

###########################################################
# TOML file I/O utilities
###########################################################

# Read toml file, or {} when it cannot be read
def read_toml_file(src, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading %s" % src)
        with open(src, "rb") as input_file:
            return tomllib.load(input_file)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            runtime.quit_program()
        return {}
