# Imports
import os
import json
import csv

# Local imports
import logger
import system
import datautils

###########################################################
# Text file I/O utilities
###########################################################

# Read text file
def read_text_file(src, verbose = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Reading %s" % src)
        with open(src, "r", encoding="utf-8") as input_file:
            return input_file.read()
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return None

# Write text file
def write_text_file(src, contents, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Writing %s" % src)
        if not pretend_run:
            parent_dir = os.path.dirname(src)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir)
            with open(src, "w", encoding="utf-8", newline='\n') as output_file:
                output_file.write(contents)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

###########################################################
# JSON file I/O utilities
###########################################################

# Parse json string
def parse_json_string(string, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Parsing %s" % string)
        json_data = json.loads(string)
        return json_data
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % string)
            logger.log_error(e)
            system.QuitProgram()
        return {}

# Read json file
def read_json_file(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return {}
        if verbose:
            logger.log_info("Reading %s" % src)
        json_data = {}
        with open(src, "r") as input_file:
            file_contents = input_file.read()
            json_data = json.loads(file_contents)
        return json_data
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            system.QuitProgram()
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
            with open(src, "w", newline='\n') as output_file:
                json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                output_file.write(json_string)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to write %s" % src)
            logger.log_error(e)
            system.QuitProgram()
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
            with open(src, "r") as input_file:
                json_data = json.loads(input_file.read())
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
                    if isinstance(json_value, bool) and json_value == False:
                        json_keys_to_remove.append(key)
                for key in json_keys_to_remove:
                    json_data.pop(key)
            if json_data is not None:
                with open(src, "w", newline='\n') as output_file:
                    json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                    output_file.write(json_string)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to clean %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Search json files
def search_json_files(src, search_values = [], search_keys = [], verbose = False, pretend_run = False, exit_on_failure = False):
    found_files = []
    for json_file in system.BuildFileListByExtensions(src, extensions = [".json"]):
        json_data = read_json_file(
            src = json_file,
            verbose = verbose,
            pretend_run = pretend_run,
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
def read_yaml_file(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        import yaml
        if not src.endswith(".yaml"):
            return {}
        if verbose:
            logger.log_info("Reading %s" % src)
        yaml_data = {}
        with open(src, "r") as input_file:
            file_contents = input_file.read()
            file_contents = file_contents.replace(u'\x81', "")
            file_contents = file_contents.replace(u'\x82', "")
            yaml_data = yaml.safe_load(file_contents)
        return yaml_data
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return {}

###########################################################
# CSV file I/O utilities
###########################################################

# Read csv file
def read_csv_file(src, headers, verbose = False, pretend_run = False, exit_on_failure = False):
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
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to read %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return []
