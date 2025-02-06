# Imports
import os, os.path
import re
import inspect
import logging
import stat
import sys
import errno
import shutil
import tempfile
import textwrap
import pathlib
import posixpath
import ntpath
import glob
import json
import csv
import time
import datetime
import urllib.parse
import collections.abc
import uuid

# Local imports
import config
import environment
import hashing
import programs
import network

# Globals
console_logger = None
file_logger = None

###########################################################

# Quit program
def QuitProgram(exit_code = -1):
    sys.exit(exit_code)

# Sleep program
def SleepProgram(seconds):
    time.sleep(seconds)

###########################################################

# Generate unique ID
def GenerateUniqueID():
    return str(uuid.uuid4())

###########################################################

# Assert that condition is true
def AssertCondition(condition, description):
    assert condition, "Condition failed: %s" % description

# Assert that variable is not none
def AssertIsNotNone(var_value, var_name):
    assert var_value is not None, "%s should not be None" % var_name

# Assert that variable is string
def AssertIsString(var_value, var_name):
    assert type(var_value) == str, "%s should be a string" % var_name

# Assert that variable is non-empty string
def AssertIsNonEmptyString(var_value, var_name):
    assert (type(var_value) == str) and (len(var_value) > 0), "%s should be a non-empty string" % var_name

# Assert that variable is non-empty string of specific length
def AssertIsStringOfSpecificLength(var_value, var_len, var_name):
    assert (type(var_value) == str) and (len(var_value) == var_len), "%s should be a string of size %s" % (var_name, var_len)

# Assert that variable is valid path
def AssertIsValidPath(var_value, var_name):
    assert IsPathValid(var_value), "%s should be a valid path" % var_name

# Assert that variable is integer
def AssertIsInt(var_value, var_name):
    assert type(var_value) == int, "%s should be an integer" % var_name

# Assert that variable is castable to integer
def AssertIsCastableToInt(var_value, var_name):
    test_value = None
    try:
        test_value = int(var_value)
    except:
        pass
    assert type(test_value) == int, "%s should be castable to an integer" % var_name

# Assert that variable is boolean
def AssertIsBool(var_value, var_name):
    assert type(var_value) == bool, "%s should be a boolean" % var_name

# Assert that variable is castable to boolean
def AssertIsCastableToBool(var_value, var_name):
    test_value = None
    try:
        if var_value == "True":
            test_value = True
        elif var_value == "False":
            test_value = False
    except:
        pass
    assert type(test_value) == bool, "%s should be castable to boolean" % var_name

# Assert that variable is list
def AssertIsList(var_value, var_name):
    assert type(var_value) == list, "%s should be an list" % var_name

# Assert that variable is dictionary
def AssertIsDictionary(var_value, var_name):
    assert type(var_value) == dict, "%s should be an dict" % var_name

# Assert that variable is dictionary and key exists
def AssertDictionaryHasKey(var_value, var_key):
    assert type(var_value) == dict and var_key in var_value, "Key '%s' not found in dictionary" % var_key

# Assert that variable is callable
def AssertCallable(var_value, var_name):
    assert callable(var_value), "%s should be a callable" % var_name

# Assert that path exists
def AssertPathExists(var_value, var_name):
    assert os.path.exists(var_value), "%s should be a path that exists" % var_name

###########################################################

# Prompt for value
def PromptForValue(description, default_value = None):
    prompt = ">>> %s: " % (description)
    if default_value:
        prompt = ">>> %s [default: %s]: " % (description, default_value)
    value = input(prompt)
    if len(value) == 0:
        return default_value
    return value

# Prompt for integer value
def PromptForIntegerValue(description, default_value = None):
    while True:
        value = PromptForValue(description, default_value)
        try:
            return int(value)
        except:
            LogWarning("That was not a valid integer, please try again")

# Prompt for url
def PromptForUrl(description, default_value = None):
    while True:
        value = PromptForValue(description, default_value)
        if network.IsUrlReachable(value):
            return value
        LogWarning("That was not a valid url, please try again")

###########################################################

# Get enclosed substrings
def FindEnclosedSubstrings(string, opening_delim = "\"", closing_delim = "\""):
    pattern = rf'(?<!\\){re.escape(opening_delim)}(.*?)(?<!\\){re.escape(closing_delim)}'
    return re.findall(pattern, string)

# Split by enclosed substrings
def SplitByEnclosedSubstrings(string, opening_delim = "\"", closing_delim = "\""):
    split_substrings = []
    pattern = rf'(?<!\\){re.escape(opening_delim)}.*?(?<!\\){re.escape(closing_delim)}'
    substring_index = 0
    enclosed_substrings = FindEnclosedSubstrings(string, opening_delim, closing_delim)
    for part in re.split(pattern, string):
        split_substrings.append(part.strip())
        if substring_index < len(enclosed_substrings):
            split_substrings.append(enclosed_substrings[substring_index].strip())
            substring_index += 1
    return [part for part in split_substrings if part]

# Remove enclosed substrings
def RemoveEnclosedSubstrings(string, opening_delim = "\"", closing_delim = "\""):
    for substring in FindEnclosedSubstrings(string, opening_delim, closing_delim):
        full_braced_substring = f"{opening_delim}{substring}{closing_delim}"
        string = string.replace(f" {full_braced_substring} ", " ")
        string = string.replace(f" {full_braced_substring}", " ")
        string = string.replace(f"{full_braced_substring} ", " ")
        string = string.replace(full_braced_substring, "")
    return string.strip()

# Get string similarity ratio
def GetStringSimilarityRatio(string1, string2):
    try:
        from thefuzz import fuzz
        return fuzz.ratio(string1, string2)
    except:
        return 0

# Check if strings are highly similar
def AreStringsHighlySimilar(string1, string2):
    ratio = GetStringSimilarityRatio(string1, string2)
    return (ratio >= 90)

# Check if strings are moderately similar
def AreStringsModeratelySimilar(string1, string2):
    ratio = GetStringSimilarityRatio(string1, string2)
    return (ratio >= 80)

# Check if strings are possibly similar
def AreStringsPossiblySimilar(string1, string2):
    ratio = GetStringSimilarityRatio(string1, string2)
    return (ratio >= 50)

# Sort strings
def SortStrings(strings):
    return sorted(strings, key=lambda item: (item, len(item)))

# Sort strings with length
def SortStringsWithLength(strings):
    return sorted(strings, key=lambda item: (len(item), item))

# Check if string starts with substring
def DoesStringStartWithSubstring(string, substring, case_sensitive = False):
    if case_sensitive:
        return string.startswith(substring)
    return string.lower().startswith(substring.lower())

# Check if string ends with substring
def DoesStringEndWithSubstring(string, substring, case_sensitive = False):
    if case_sensitive:
        return string.endswith(substring)
    return string.lower().endswith(substring.lower())

# Trim substring from start
def TrimSubstringFromStart(string, substring, case_sensitive = False):
    if DoesStringStartWithSubstring(string, substring, case_sensitive):
        return string[len(substring):]
    return string

# Trim substring from end
def TrimSubstringFromEnd(string, substring, case_sensitive = False):
    if DoesStringEndWithSubstring(string, substring, case_sensitive):
        return string[:-len(substring)]
    return string

# Remove string escape sequences
def RemoveStringEscapeSequences(string):
    pattern = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return pattern.sub("", string)

# Remove string tag sequences
def RemoveStringTagSequences(string):
    pattern = re.compile(r'</?[^>]+>')
    return pattern.sub("", string)

# Get datetime from string
def GetDatetimeFromString(string, format_code):
    return datetime.datetime.strptime(string, format_code)

# Get datetime from unknown string
def GetDatetimeFromUnknownString(string):
    try:
        import dateutil.parser
        return dateutil.parser.parse(string)
    except:
        return None

# Convert datetime to string
def GetStringFromDatetime(date_time, format_code):
    return date_time.strftime(format_code)

# Convert datetime to string
def ConvertDateString(string, old_format_code, new_format_code):
    date_time = GetDatetimeFromString(string, old_format_code)
    if date_time:
        return GetStringFromDatetime(date_time, new_format_code)
    return None

# Convert unknown date string
def ConvertUnknownDateString(string, new_format_code):
    date_time = GetDatetimeFromUnknownString(string)
    if date_time:
        return GetStringFromDatetime(date_time, new_format_code)
    return None

# Encode url string
def EncodeUrlString(string, use_plus = False):
    if use_plus:
        return urllib.parse.quote_plus(string)
    else:
        return urllib.parse.quote(string)

# Join strings as url
def JoinStringsAsUrl(string1, string2, allow_fragments = True):
    return urllib.parse.urljoin(string1, string2, allow_fragments = allow_fragments)

# Strip string query params
def StripStringQueryParams(string):
    return urllib.parse.urlunparse(urllib.parse.urlparse(string)._replace(query=""))

# Get slug string
def GetSlugString(string):
    string = string.strip().lower()
    string = string.replace(" ", "_")
    string = re.sub(r'[^a-z0-9_]', '', string)
    string = string.replace("__", "_")
    return string

###########################################################

# Capitalize text
def CapitalizeText(text):
    if len(text) == 0:
        return ""
    elif len(text) == 1:
        return text.upper()
    else:
        words = []
        for index, word in enumerate(text.split(" ")):
            for filler_word in config.filler_words:
                if index != 0 and word.lower() == filler_word.lower():
                    words.append(word)
                    break
            else:
                if len(word) == 1:
                    words.append(word[0].upper())
                elif len(word) >= 2:
                    words.append(word[0].upper() + word[1:])
        return " ".join(words)

# Wrap text to lines
def WrapTextToLines(text, width = 80, spacer = "."):
    wrapped_lines = []
    text_lines = text.split("\n")
    for index, line in enumerate(text_lines):
        for wrapped_line in textwrap.wrap(line.strip(), width=width):
            wrapped_lines.append(wrapped_line)
        if index < len(text_lines) - 1 and len(spacer):
            wrapped_lines.append(spacer)
    return wrapped_lines

# Clean rich text
def CleanRichText(text):
    new_text = text
    try:
        import unidecode
        new_text = unidecode.unidecode(new_text)
    except:
        pass
    for old, new in config.rich_text_replacements.items():
        new_text = new_text.replace(old, new)
    new_text = new_text.encode("ascii", "ignore").decode()
    return new_text.strip()

# Clean web text
def CleanWebText(text):
    new_text = CleanRichText(text)
    for old, new in config.web_text_replacements.items():
        new_text = new_text.replace(old, new)
    return new_text

# Extract web text
def ExtractWebText(text):
    try:
        import html_text
        return html_text.extract_text(text)
    except:
        return None

###########################################################

# Merge dictionaries
def MergeDictionaries(dict1, dict2, merge_type = None):
    if isinstance(dict1, dict) and isinstance(dict2, dict):
        try:
            import mergedeep
            if merge_type == config.MergeType.REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.REPLACE)
            elif merge_type == config.MergeType.ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.ADDITIVE)
            elif merge_type == config.MergeType.SAFE_REPLACE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_REPLACE)
            elif merge_type == config.MergeType.SAFE_ADDITIVE:
                return mergedeep.merge(dict1, dict2, strategy=mergedeep.Strategy.TYPESAFE_ADDITIVE)
            else:
                return mergedeep.merge(dict1, dict2)
        except:
            return dict1
    elif isinstance(dict1, dict) and not isinstance(dict2, dict):
        return dict1
    elif not isinstance(dict1, dict) and isinstance(dict2, dict):
        return dict2
    else:
        return None

# Merge lists
def MergeLists(list1, list2, merge_type = None):
    if isinstance(list1, list) and isinstance(list2, list):
        return sorted(set(list1 + list2))
    elif isinstance(list1, list) and not isinstance(list2, list):
        return list1
    elif not isinstance(list1, list) and isinstance(list2, list):
        return list2
    else:
        return None

# Merge data
def MergeData(data1, data2, merge_type = None):
    if isinstance(data1, dict) or isinstance(data2, dict):
        return MergeDictionaries(
            dict1 = data1,
            dict2 = data2,
            merge_type = merge_type)
    elif isinstance(data1, list) or isinstance(data2, list):
        return MergeLists(
            list1 = data1,
            list2 = data2,
            merge_type = merge_type)
    else:
        if data1 and data2:
            return [data1, data2]
        elif data1 and not data2:
            return data1
        elif not data1 and data2:
            return data2
        else:
            return None

# Deduplicate adjacent lines
def DeduplicateAdjacentLines(lines):
    new_lines = []
    for line in lines:
        if len(new_lines) == 0 or line != new_lines[-1]:
            new_lines.append(line)
    return new_lines

# Determine if container is iterable
def IsIterableContainer(obj):
    return isinstance(obj, collections.abc.Iterable)

# Determine if container is iterable non-string
def IsIterableNonString(obj):
    if isinstance(obj, str):
        return False
    return IsIterableContainer(obj)

###########################################################

# Get source info
def GetSourceInfo():
    frame = inspect.currentframe().f_back
    file_name = os.path.basename(frame.f_code.co_filename)
    line_number = frame.f_lineno
    return f"({file_name}:{line_number})"

# Get backtrace
def GetBacktrace():
    stack = inspect.stack()
    backtrace = []
    for frame_info in stack:
        filename = frame_info.filename
        lineno = frame_info.lineno
        name = frame_info.function
        backtrace.append(f"File: {filename}, Line: {lineno}, Function: {name}")
    return "\n".join(backtrace)

###########################################################

# Get console logger
def GetConsoleLogger():
    global console_logger
    if not console_logger:
        console_logger = logging.getLogger("ConsoleLogger")
        console_logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        console_logger.addHandler(console_handler)
    return console_logger

# Get file logger
def GetFileLogger():
    global file_logger
    if not file_logger:
        file_logger = logging.getLogger("FileLogger")
        file_logger.setLevel(logging.DEBUG)
        file_handler = logging.FileHandler(environment.GetLogFile(), mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)
        file_logger.addHandler(file_handler)
    return file_logger

# Add logging context
def AddLoggingContext(
    message,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_name = None):
    context = ""
    if game_supercategory:
        context += "[%s]" % game_supercategory.val()
    if game_category:
        context += "[%s]" % game_category.val()
    if game_subcategory:
        context += "[%s]" % game_subcategory.val()
    if game_name:
        context += "[%s]" % game_name.val()
    if len(context) > 0:
        return f"{context} {message}"
    return message

# Log info
def LogInfo(
    message,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_name = None):
    message = AddLoggingContext(
        message = message,
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name)
    console_logger = GetConsoleLogger()
    file_logger = GetFileLogger()
    if console_logger:
        console_logger.info(message)
    if file_logger:
        file_logger.info(message)

# Log warning
def LogWarning(
    message,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_name = None):
    message = AddLoggingContext(
        message = message,
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name)
    console_logger = GetConsoleLogger()
    file_logger = GetFileLogger()
    if console_logger:
        console_logger.warning(message)
    if file_logger:
        file_logger.warning(message)

# Log error
def LogError(
    message,
    game_supercategory = None,
    game_category = None,
    game_subcategory = None,
    game_name = None,
    quit_program = False):
    message = AddLoggingContext(
        message = message,
        game_supercategory = game_supercategory,
        game_category = game_category,
        game_subcategory = game_subcategory,
        game_name = game_name)
    console_logger = GetConsoleLogger()
    file_logger = GetFileLogger()
    if console_logger:
        console_logger.error(GetBacktrace())
        console_logger.error(message)
    if file_logger:
        file_logger.error(GetBacktrace())
        file_logger.error(message)
    if quit_program:
        QuitProgram()

# Log percent complete
def LogPercentComplete(percent_complete):
    print(">>> Percent complete: %s%% " % percent_complete, end='\r', flush=True)

###########################################################

# Display table
def DisplayTable(table_data):
    try:
        import texttable
        table = texttable.Texttable()
        table.set_max_width(0)
        for index, entry in enumerate(table_data):
            if index == 0:
                table.header(entry.keys())
            table.add_row(entry.values())
        print(table.draw())
        return True
    except Exception as e:
        LogError(e)
        return False

###########################################################

# Check if path is valid
# https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
# https://gist.github.com/mo-han/240b3ef008d96215e352203b88be40db
def IsPathValid(path):
    try:
        if not isinstance(path, str) or not path or len(path) == 0:
            return False
        if os.name == "nt":
            drive, path = os.path.splitdrive(path)
            if not os.path.isdir(drive):
                drive = os.environ.get("SystemDrive", "C:")
            if not os.path.isdir(drive):
                drive = ""
        else:
            drive = ""
        parts = pathlib.Path(path).parts
        check_list = [os.path.join(*parts), *parts]
        for x in check_list:
            try:
                os.lstat(drive + x)
            except OSError as e:
                if hasattr(e, "winerror") and e.winerror == 123:
                    return False
                elif e.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
                    return False
    except TypeError:
        return False
    else:
        return True

# Check if path is the parent of another
def IsParentPath(parent_path, child_path):
    try:
        parent = pathlib.Path(parent_path).resolve()
        child = pathlib.Path(child_path).resolve()
        return child.is_relative_to(parent)
    except ValueError:
        return False

# Check if path exists
def DoesPathExist(path, case_sensitive_paths = True, partial_paths = False):
    if not path:
        return False
    if case_sensitive_paths:
        return os.path.exists(path)
    elif partial_paths:
        path_parent = str(pathlib.Path(path).parent)
        path_name = str(pathlib.Path(path).name)
        if os.path.isdir(path_parent):
            for obj in os.listdir(path_parent):
                if obj.startswith(path_name):
                    return True
    else:
        path_parent = str(pathlib.Path(path).parent)
        path_name = str(pathlib.Path(path).name)
        for obj in os.listdir(path_parent):
            if path_name.lower() == obj.lower():
                return True
    return False

# Check if path is a file
def IsPathFile(path):
    if not IsPathValid(path):
        return False
    if not DoesPathExist(path):
        return False
    return os.path.isfile(path)

# Check if path is a directory
def IsPathDirectory(path):
    if not IsPathValid(path):
        return False
    if not DoesPathExist(path):
        return False
    return os.path.isdir(path)

# Check if path is a symlink
def IsPathSymlink(path):
    if not IsPathValid(path):
        return False
    if not DoesPathExist(path):
        return False
    return os.path.islink(path)

# Check if path is file or directory
def IsPathFileOrDirectory(path):
    if not IsPathValid(path):
        return False
    if not DoesPathExist(path):
        return False
    return os.path.isfile(path) or os.path.isdir(path) and not os.path.islink(path)

# Check if drive letter is valid
def IsDriveLetterValid(drive_letter):
    if not drive_letter or not isinstance(drive_letter, str) or len(drive_letter) == 0:
        return False
    return drive_letter.isalpha()

# Replace invalid path characters
def ReplaceInvalidPathCharacters(path):

    # Rich text
    new_path = CleanRichText(path)

    # Printable characters
    for old, new in config.path_text_replacements.items():
        new_path = new_path.replace(old, new)

    # Non-printable characters
    for i in range(0, 32):
        new_path = new_path.replace(chr(i), "")

    # Trailing space or dot
    new_path = new_path.rstrip(" .")

    # Excessive spaces
    new_path = " ".join(new_path.split())

    # Return new path
    return new_path

###########################################################

# Determine if file is correctly headered
def IsFileCorrectlyHeadered(src, expected_header):
    if os.path.isfile(src):
        with open(src, "rb") as file:
            actual_header = file.read(len(expected_header))
            if isinstance(expected_header, bytes):
                return (actual_header == expected_header)
            elif isinstance(expected_header, str):
                return (actual_header == bytes(expected_header, "utf-8"))
    return False

# Replace strings in file
def ReplaceStringsInFile(src, replacements = [], verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                LogInfo("Path %s is not a file" % src)
            return False
        if verbose:
            LogInfo("Replacing lines in file %s" % src)
        if not pretend_run:
            src_contents = ""
            with open(src, "r", encoding="utf-8") as f:
                src_contents = f.read()
            for entry in replacements:
                entry_from = entry["from"]
                entry_to = entry["to"]
                if entry_from and entry_to:
                    src_contents = src_contents.replace(entry_from, entry_to)
            with open(src, "w", encoding="utf-8") as f:
                f.write(src_contents)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to replace strings in file %s" % src)
            LogError(e)
            QuitProgram()
        return False

# Append line to file
def AppendLineToFile(src, line, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                LogInfo("Path %s is not a file" % src)
            return False
        if verbose:
            LogInfo("Adding line '%s' to file %s" % (line, src))
        if not pretend_run:
            with open(src, "r+", encoding="utf8") as f:
                ends_with_newline = True
                for src_line in f.readlines():
                    ends_with_newline = src_line.endswith("\n")
                    if src_line.rstrip("\n\r") == line:
                        break
                else:
                    if not ends_with_newline:
                        f.write("\n")
                    f.write(line + "\n")
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to add line '%s' to file %s" % (line, src))
            LogError(e)
            QuitProgram()
        return False

# Sort file contents
def SortFileContents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                LogInfo("Path %s is not a file" % src)
            return False
        if verbose:
            LogInfo("Sorting contents of file %s" % src)
        if not pretend_run:
            sorted_contents = ""
            with open(src, "r", encoding="utf8") as f:
                for line in sorted(f):
                    sorted_contents += line
            with open(src, "w", encoding="utf8") as f:
                f.write(sorted_contents)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to sort contents of file %s" % src)
            LogError(e)
            QuitProgram()
        return False

###########################################################

# Remove empty directories
def RemoveEmptyDirectories(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for empty_dir in BuildEmptyDirectoryList(dir):
        success = RemoveDirectory(
            dir = empty_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Replace symlinked directories
def ReplaceSymlinkedDirectories(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    for symlink_dir in BuildSymlinkDirectoryList(dir):
        success = RemoveSymlink(
            symlink = symlink_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = MakeDirectory(
            dir = symlink_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Lowercase all paths
def LowercaseAllPaths(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Lowercasing all paths in directory %s" % dir)
        def onFoundItems(root, items):
            for name in items:
                if not pretend_run:
                    before = os.path.join(root, name)
                    after = os.path.join(root, name.lower())
                    if before != after:
                        os.rename(before, after)
        for root, dirs, files in os.walk(dir, topdown = False):
            onFoundItems(root, dirs)
            onFoundItems(root, files)
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to lowercase directory %s" % dir)
            LogError(e)
            QuitProgram()

###########################################################

# Touch file
def TouchFile(src, contents = "", contents_mode = "w", encoding = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Touching file %s" % src)
        if not pretend_run:
            os.makedirs(GetFilenameDirectory(src), exist_ok = True)
            if len(contents):
                if encoding:
                    with open(src, contents_mode, encoding) as f:
                        f.write(contents)
                else:
                    with open(src, contents_mode) as f:
                        f.write(contents)
            else:
                open(src, "a").close()
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to touch file %s" % src)
            LogError(e)
            QuitProgram()
        return False

# Chmod file or directory
def ChmodFileOrDirectory(src, perms, dperms = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Changing permissions of %s to %s" % (src, str(perms)))
        if not pretend_run:
            if os.path.isfile(src):
                os.chmod(src, int(str(perms), base=8))
            elif os.path.isdir(src):
                for root, dirs, files in os.walk(src):
                    for f in files:
                        os.chmod(os.path.join(root, f), int(str(perms), base=8))
                    for d in dirs:
                        if dperms:
                            os.chmod(os.path.join(root, d), int(str(dperms), base=8))
                        else:
                            os.chmod(os.path.join(root, d), int(str(perms), base=8))
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to change permissions of %s to %s" % (src, str(perms)))
            LogError(e)
            QuitProgram()
        return False

# Mark as executable
def MarkAsExecutable(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Marking %s as executable" % src)
        if not pretend_run:
            st = os.stat(src)
            os.chmod(src, st.st_mode | stat.S_IEXEC)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to mark %s as executable" % src)
            LogError(e)
            QuitProgram()
        return False

# Create temporary directory
def CreateTemporaryDirectory(verbose = False, pretend_run = False):
    if verbose:
        LogInfo("Creating temporary directory")
    dir = ""
    if not pretend_run:
        dir = os.path.realpath(tempfile.mkdtemp())
        if verbose:
            LogInfo("Created temporary directory %s" % dir)
    if not os.path.isdir(dir):
        return (False, "Unable to create temporary directory")
    return (True, dir)

# Create symlink
def CreateSymlink(src, dest, cwd = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Creating symlink from %s to %s" % (src, dest))
        if not pretend_run:
            if cwd:
                os.chdir(cwd)
            os.symlink(src, dest, target_is_directory = os.path.isdir(src))
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to create symlink from %s to %s" % (src, dest))
            LogError(e)
            QuitProgram()
        return False

# Copy file or directory
def CopyFileOrDirectory(
    src,
    dest,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if skip_existing and DoesPathExist(dest, case_sensitive_paths):
            return True
        if skip_identical:
            if hashing.AreFilesIdentical(
                first = src,
                second = dest,
                case_sensitive_paths = case_sensitive_paths,
                verbose = verbose,
                exit_on_failure = exit_on_failure):
                return True
        if verbose:
            LogInfo("Copying %s to %s" % (src, dest))
        if not pretend_run:
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy(src, dest)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to copy %s to %s" % (src, dest))
            LogError(e)
            QuitProgram()
        return False

# Move file or directory
def MoveFileOrDirectory(
    src,
    dest,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if skip_existing and DoesPathExist(dest, case_sensitive_paths):
            return True
        if skip_identical:
            if hashing.AreFilesIdentical(
                first = src,
                second = dest,
                case_sensitive_paths = case_sensitive_paths,
                verbose = verbose,
                exit_on_failure = exit_on_failure):
                return True
        if verbose:
            LogInfo("Moving %s to %s" % (src, dest))
        if not pretend_run:
            shutil.move(src, dest)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to move %s to %s" % (src, dest))
            LogError(e)
            QuitProgram()
        return False

# Transfer file
def TransferFile(
    src,
    dest,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if skip_existing and DoesPathExist(dest, case_sensitive_paths):
            return True
        if skip_identical:
            if hashing.AreFilesIdentical(
                first = src,
                second = dest,
                case_sensitive_paths = case_sensitive_paths,
                verbose = verbose,
                exit_on_failure = exit_on_failure):
                return True
        if verbose:
            LogInfo("Transferring %s to %s" % (src, dest))
        if not pretend_run:
            total_size = GetFileSize(src)
            progress_bar = None
            progress_callback = None
            if show_progress:
                import tqdm
                progress_bar = tqdm.tqdm(total = total_size)
                progress_callback = lambda copied, total_copied, total: progress_bar.update(copied)
            with open(src, "rb") as fsrc:
                with open(dest, "wb") as fdest:
                    num_bytes_transferred = 0
                    while True:
                        buf = fsrc.read(config.transfer_chunk_size)
                        if not buf:
                            break
                        fdest.write(buf)
                        num_bytes_transferred += len(buf)
                        if callable(progress_callback):
                            progress_callback(len(buf), num_bytes_transferred, total_size)
            shutil.copymode(src, dest)
            if delete_afterwards:
                os.remove(src)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to transfer %s to %s" % (src, dest))
            LogError(e)
            QuitProgram()
        return False

# Make directory
def MakeDirectory(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isdir(dir):
            if verbose:
                LogInfo("Making directory %s" % dir)
            if not pretend_run:
                os.makedirs(dir)
        return True
    except Exception as e:
        if not os.path.isdir(dir):
            if exit_on_failure:
                LogError("Unable to make directory %s" % dir)
                LogError(e)
                QuitProgram()
            return False
        return True

# Remove file
def RemoveFile(file, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Removing file %s" % file)
        if not pretend_run:
            if os.path.isfile(file):
                os.remove(file)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove file %s" % file)
            LogError(e)
            QuitProgram()
        return False

# Remove symlink
def RemoveSymlink(symlink, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Removing symlink %s" % symlink)
        if not pretend_run:
            if os.path.islink(symlink):
                os.unlink(symlink)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove symlink %s" % symlink)
            LogError(e)
            QuitProgram()
        return False

# Remove directory
def RemoveDirectory(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Removing directory %s" % dir)
        if not pretend_run:
            if os.path.isdir(dir):
                shutil.rmtree(dir)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove directory %s" % dir)
            LogError(e)
            QuitProgram()
        return False

# Remove directory contents
def RemoveDirectoryContents(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            LogInfo("Removing contents of directory %s" % dir)
        if not pretend_run:
            for root, dirs, files in os.walk(dir):
                for f in files:
                    os.unlink(os.path.join(root, f))
                for d in dirs:
                    def onError(func, path, exc):
                        excvalue = exc[1]
                        if func in (os.rmdir, os.remove) and excvalue.errno == errno.EACCES:
                            os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
                            func(path)
                        else:
                            raise
                    if not os.path.islink(os.path.join(root, d)):
                        shutil.rmtree(os.path.join(root, d), ignore_errors=False, onerror=onError)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove contents of directory %s" % dir)
            LogError(e)
            QuitProgram()
        return False

###########################################################

# Copy contents
def CopyContents(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not DoesPathExist(src, case_sensitive_paths):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot copy" % src)
            QuitProgram()
    file_list = BuildFileList(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = MakeDirectory(
            dir = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = TransferFile(
            src = input_file,
            dest = output_file,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Move contents
def MoveContents(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not DoesPathExist(src, case_sensitive_paths):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot move" % src)
            QuitProgram()
    file_list = BuildFileList(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = MakeDirectory(
            dir = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = TransferFile(
            src = input_file,
            dest = output_file,
            delete_afterwards = True,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Copy globbed files
def CopyGlobbedFiles(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    glob_source_dir = GetFilenameDirectory(glob_pattern)
    glob_files = ConvertFileListToRelativePaths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    for glob_file in glob_files:
        success = MakeDirectory(
            dir = os.path.join(dest_dir, GetFilenameDirectory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = TransferFile(
            src = os.path.join(glob_source_dir, glob_file),
            dest = os.path.join(dest_dir, glob_file),
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Move globbed files
def MoveGlobbedFiles(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    glob_source_dir = GetFilenameDirectory(glob_pattern)
    glob_files = ConvertFileListToRelativePaths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    for glob_file in glob_files:
        success = MakeDirectory(
            dir = os.path.join(dest_dir, GetFilenameDirectory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = TransferFile(
            src = os.path.join(glob_source_dir, glob_file),
            dest = os.path.join(dest_dir, glob_file),
            delete_afterwards = True,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Smart copy
def SmartCopy(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = MakeDirectory(
        dir = GetFilenameDirectory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.token_glob in GetFilenameBasename(src):
        return CopyGlobbedFiles(
            glob_pattern = src,
            dest_dir = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        if os.path.isdir(src):
            return CopyContents(
                src = src,
                dest = dest,
                show_progress = show_progress,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = case_sensitive_paths,
                ignore_symlinks = ignore_symlinks,
                follow_symlink_dirs = follow_symlink_dirs,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            return TransferFile(
                src = src,
                dest = dest,
                show_progress = show_progress,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = case_sensitive_paths,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    return True

# Smart move
def SmartMove(
    src,
    dest,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    success = MakeDirectory(
        dir = GetFilenameDirectory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.token_glob in GetFilenameBasename(src):
        return MoveGlobbedFiles(
            glob_pattern = src,
            dest_dir = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        if os.path.isdir(src):
            return MoveContents(
                src = src,
                dest = dest,
                show_progress = show_progress,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = case_sensitive_paths,
                ignore_symlinks = ignore_symlinks,
                follow_symlink_dirs = follow_symlink_dirs,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            return TransferFile(
                src = src,
                dest = dest,
                delete_afterwards = True,
                show_progress = show_progress,
                skip_existing = skip_existing,
                skip_identical = skip_identical,
                case_sensitive_paths = case_sensitive_paths,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    return True

# Smart transfer
def SmartTransfer(
    src,
    dest,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if delete_afterwards:
        return SmartMove(
            src = src,
            dest = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            ignore_symlinks = ignore_symlinks,
            follow_symlink_dirs = follow_symlink_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        return SmartCopy(
            src = src,
            dest = dest,
            show_progress = show_progress,
            skip_existing = skip_existing,
            skip_identical = skip_identical,
            case_sensitive_paths = case_sensitive_paths,
            ignore_symlinks = ignore_symlinks,
            follow_symlink_dirs = follow_symlink_dirs,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Sync contents
def SyncContents(
    src,
    dest,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not DoesPathExist(src):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot sync" % src)
            QuitProgram()
    success = MakeDirectory(
        dir = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    success = RemoveDirectoryContents(
        dir = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return CopyContents(
        src = src,
        dest = dest,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Sync data
def SyncData(data_src, data_dest, verbose = False, pretend_run = False, exit_on_failure = False):
    is_glob_src = (config.token_glob in GetFilenameBasename(data_src))
    is_glob_dest = (config.token_glob in GetFilenameBasename(data_dest))
    if is_glob_src and is_glob_dest:
        return CopyGlobbedFiles(
            glob_pattern = data_src,
            dest_dir = os.path.dirname(data_dest),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isdir(data_src):
        return SyncContents(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isfile(data_src):
        return SmartCopy(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run)

# Remove object
def RemoveObject(obj, verbose = False, pretend_run = False, exit_on_failure = False):
    if os.path.isfile(obj):
        return RemoveFile(
            file = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.islink(obj):
        return RemoveSymlink(
            symlink = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isdir(obj):
        success_contents = RemoveDirectoryContents(
            dir = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        success_dir = RemoveDirectory(
            dir = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success_contents and success_dir
    return False

###########################################################

# Read json file
def ReadJsonFile(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return {}
        if verbose:
            LogInfo("Reading %s" % src)
        json_data = {}
        with open(src, "r") as input_file:
            file_contents = input_file.read()
            json_data = json.loads(file_contents)
        return json_data
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to read %s" % src)
            LogError(e)
            QuitProgram()
        return {}

# Write json file
def WriteJsonFile(src, json_data, sort_keys = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            LogInfo("Writing %s" % src)
        if not pretend_run:
            with open(src, "w", newline='\n') as output_file:
                json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                output_file.write(json_string)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to write %s" % src)
            LogError(e)
            QuitProgram()
        return False

# Clean json file
def CleanJsonFile(src, sort_keys = False, remove_empty_values = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            LogInfo("Cleaning %s" % src)
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
            LogError("Unable to clean %s" % src)
            LogError(e)
            QuitProgram()
        return False

###########################################################

# Read yaml file
def ReadYamlFile(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        import yaml
        if not src.endswith(".yaml"):
            return {}
        if verbose:
            LogInfo("Reading %s" % src)
        yaml_data = {}
        with open(src, "r") as input_file:
            file_contents = input_file.read()
            file_contents = file_contents.replace(u'\x81', "")
            file_contents = file_contents.replace(u'\x82', "")
            yaml_data = yaml.safe_load(file_contents)
        return yaml_data
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to read %s" % src)
            LogError(e)
            QuitProgram()
        return {}

###########################################################

# Read csv file
def ReadCsvFile(src, headers, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".csv"):
            return []
        if verbose:
            LogInfo("Reading %s" % src)
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
            LogError("Unable to read %s" % src)
            LogError(e)
            QuitProgram()
        return []

###########################################################

# Prune paths
def PrunePaths(paths, excludes = []):
    new_paths = set()
    for path in paths:
        should_add = True
        for exclude in excludes:
            if path.startswith(exclude):
                should_add = False
        if should_add:
            new_paths.add(path)
    return SortStrings(new_paths)

# Prune child paths
def PruneChildPaths(paths):
    new_paths = set()
    for path in SortStrings(paths):
        if not any(IsParentPath(added_path, path) for added_path in new_paths):
            new_paths.add(path)
    return SortStrings(new_paths)

# Build file list
def BuildFileList(root, excludes = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    files = []
    if not IsPathValid(root):
        return files
    absolute_root = os.path.abspath(root)
    if os.path.isdir(root):
        for root, dirnames, filenames in os.walk(root, followlinks = follow_symlink_dirs):
            for filename in filenames:
                location = os.path.abspath(os.path.join(root, filename))
                if ignore_symlinks and os.path.islink(location):
                    continue
                if use_relative_paths:
                    if len(new_relative_path) and not new_relative_path.endswith(config.os_pathsep):
                        new_relative_path += config.os_pathsep
                    files.append(location.replace(absolute_root + os.sep, new_relative_path))
                else:
                    files.append(location)
    elif os.path.isfile(root):
        location = os.path.abspath(root)
        if not ignore_symlinks or ignore_symlinks and not os.path.islink(location):
            if use_relative_paths:
                if len(new_relative_path) and not new_relative_path.endswith(config.os_pathsep):
                    new_relative_path += config.os_pathsep
                files.append(location.replace(absolute_root + os.sep, new_relative_path))
            else:
                files.append(location)
    return PrunePaths(files, excludes)

# Build file list by extensions
def BuildFileListByExtensions(root, excludes = [], extensions = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    files = []
    for file in BuildFileList(root, excludes, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs):
        base, ext = GetFilenameSplit(file)
        if isinstance(extensions, list) and len(extensions) > 0:
            if ext in extensions or ext.lower() in extensions or ext.upper() in extensions:
                files.append(file)
        else:
            files.append(file)
    return SortStrings(files)

# Build directory list
def BuildDirectoryList(root, excludes = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    directories = []
    if not IsPathValid(root):
        return directories
    absolute_root = os.path.abspath(root)
    if os.path.isdir(absolute_root):
        directories.append(absolute_root)
    for root, dirnames, filenames in os.walk(root, followlinks = follow_symlink_dirs):
        for dirname in dirnames:
            location = os.path.abspath(os.path.join(root, dirname))
            if ignore_symlinks and os.path.islink(location):
                continue
            if use_relative_paths:
                if len(new_relative_path) and not new_relative_path.endswith(config.os_pathsep):
                    new_relative_path += config.os_pathsep
                directories.append(location.replace(absolute_root + os.sep, new_relative_path))
            else:
                directories.append(location)
    return PrunePaths(directories, excludes)

# Build empty directory list
def BuildEmptyDirectoryList(root, excludes = [], new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in BuildDirectoryList(root, excludes, new_relative_path, use_relative_paths):
        if IsDirectoryEmpty(potential_dir):
            directories.append(potential_dir)
    return directories

# Build symlink directory list
def BuildSymlinkDirectoryList(root, excludes = [], new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in BuildDirectoryList(root, excludes, new_relative_path, use_relative_paths):
        if os.path.islink(potential_dir):
            directories.append(potential_dir)
    return directories

###########################################################

# Convert to top level paths
def ConvertToTopLevelPaths(path_list, path_root = None, only_files = False, only_dirs = False):
    top_level_paths = set()
    for path in path_list:
        path_offset = GetFilenameDriveOffset(path)
        path_front = GetFilenameFront(path_offset)
        should_save_path = False
        if IsPathValid(path_root):
            path_full = os.path.join(path_root, path_front)
            if only_files and os.path.isfile(path_full):
                should_save_path = True
            elif only_dirs and os.path.isdir(path_full):
                should_save_path = True
        else:
            should_save_path = True
        if should_save_path:
            top_level_paths.add(path_front)
    return SortStrings(top_level_paths)

# Convert file list to relative paths
def ConvertFileListToRelativePaths(file_list, base_dir):
    replacement = NormalizeFilePath(base_dir, separator = config.os_pathsep)
    if not replacement.endswith(config.os_pathsep):
        replacement += config.os_pathsep
    relative_file_list = []
    for filename in file_list:
        normalized_filename = NormalizeFilePath(filename, separator = config.os_pathsep)
        normalized_filename = normalized_filename.replace(replacement, "")
        relative_file_list.append(normalized_filename)
    return SortStrings(relative_file_list)

# Convert file list to absolute paths
def ConvertFileListToAbsolutePaths(file_list, base_dir):
    absolute_file_list = []
    for filename in file_list:
        absolute_file_list.append(os.path.join(base_dir, filename))
    return SortStrings(absolute_file_list)

# Normalize file path
def NormalizeFilePath(path, force_posix = False, force_windows = False, separator = os.sep):
    normalized_path = path
    if force_posix:
        normalized_path = posixpath.normpath(path)
    elif force_windows:
        normalized_path = ntpath.normpath(path)
    else:
        normalized_path = os.path.normpath(path)
    normalized_path = normalized_path.replace("\\", separator)
    return normalized_path

# Split file path
def SplitFilePath(path, splitter):
    split_paths = []
    for idx, part in enumerate(path.split(splitter)):
        norm_part = NormalizeFilePath(part)
        if idx == 0:
            split_paths.append(norm_part)
        else:
            split_paths.append(GetFilenameDriveOffset(norm_part))
    return split_paths

# Rebase file path
def RebaseFilePath(path, old_base_path, new_base_path):
    norm_path = NormalizeFilePath(path)
    norm_old_base_path = NormalizeFilePath(old_base_path)
    norm_new_base_path = NormalizeFilePath(new_base_path)
    rebased_path = NormalizeFilePath(norm_path.replace(norm_old_base_path, norm_new_base_path))
    return rebased_path

# Rebase file paths
def RebaseFilePaths(paths, old_base_path, new_base_path):
    rebased_paths = []
    for path in paths:
        rebased_paths.append(RebaseFilePath(path, old_base_path, new_base_path))
    return rebased_paths

# Join paths
def JoinPaths(*paths):
    processed_paths = []
    for path in paths:
        if isinstance(path, config.EnumType):
            processed_paths.append(path.val())
        elif isinstance(path, str):
            processed_paths.append(path)
        else:
            raise TypeError(f"Path {path} must be a string or an Enum, not {type(path)}.")
    return os.path.join(*processed_paths)

###########################################################

# Get directory name
def GetDirectoryName(path):
    return str(pathlib.Path(path).name)

# Get directory parts
def GetDirectoryParts(path):
    return list(pathlib.Path(path).parts)

# Get directory parent
def GetDirectoryParent(path):
    return str(pathlib.Path(path).parent)

# Get directory front
def GetDirectoryFront(path):
    for part in GetDirectoryParts(path):
        return part
    return ""

# Get directory size
def GetDirectorySize(path):
    return sum(p.stat().st_size for p in pathlib.Path(path).rglob('*'))

# Get directory contents
def GetDirectoryContents(path, excludes = []):
    contents = []
    if DoesPathExist(path):
        if os.path.isdir(path):
            contents = os.listdir(path)
    return PrunePaths(contents, excludes)

# Get directory anchor
def GetDirectoryAnchor(path):
    if path.startswith(config.drive_root_posix):
        return str(pathlib.PurePosixPath(path).anchor)
    else:
        return str(pathlib.PureWindowsPath(path).anchor)

# Get directory drive
def GetDirectoryDrive(path):
    anchor = GetDirectoryAnchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Get directory drive offset
def GetDirectoryDriveOffset(path):
    anchor = GetDirectoryAnchor(path)
    if len(anchor) == 0:
        return path
    return path[len(anchor):]

# Check if directory is empty
def IsDirectoryEmpty(path):
    return len(GetDirectoryContents(path)) == 0

# Check if directory contains files
def DoesDirectoryContainFiles(path, recursive = True):
    if recursive:
        return len(BuildFileList(path)) > 0
    else:
        files = []
        for obj in GetDirectoryContents(path):
            obj_path = os.path.join(path, obj)
            if os.path.isfile(obj_path):
                files.append(obj)
        return len(files)

# Check if directory contains files by extensions
def DoesDirectoryContainFilesByExtensions(path, extensions = [], recursive = True):
    if recursive:
        return len(BuildFileListByExtensions(path, extensions = extensions)) > 0
    else:
        files = []
        for obj in GetDirectoryContents(path):
            obj_path = os.path.join(path, obj)
            if os.path.isfile(obj_path):
                for file_type in extensions:
                    if obj_path.endswith(file_type):
                        files.append(obj)
        return len(files)

# Check if directory contains symlink dirs
def DoesDirectoryContainSymlinkDirs(path):
    return len(BuildSymlinkDirectoryList(path)) > 0

# Get directory info
def GetDirectoryInfo(path):
    info = {}
    info["orig"] = path
    info["name"] = GetDirectoryName(path)
    info["parts"] = GetDirectoryParts(path)
    info["parent"] = GetDirectoryParent(path)
    info["front"] = GetDirectoryFront(path)
    info["size"] = GetDirectorySize(path)
    info["contents"] = GetDirectoryContents(path)
    info["anchor"] = GetDirectoryAnchor(path)
    info["drive"] = GetDirectoryDrive(path)
    info["drive_offset"] = GetDirectoryDriveOffset(path)
    info["is_empty"] = IsDirectoryEmpty(path)
    info["has_files"] = DoesDirectoryContainFiles(path)
    return info

###########################################################

# Get filename parts
def GetFilenameParts(path):
    return list(pathlib.Path(path).parts)

# Get filename directory
def GetFilenameDirectory(path):
    return str(pathlib.Path(path).parent)

# Get filename front
def GetFilenameFront(path):
    for part in GetFilenameParts(path):
        return part
    return ""

# Get filename split
def GetFilenameSplit(path):
    filename_ext = GetFilenameExtension(path)
    filename_remainder = path[:-(len(filename_ext))]
    return [filename_remainder, filename_ext]

# Get filename basename
def GetFilenameBasename(path):
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if path.endswith(tarball_ext):
            return path[:-len(tarball_ext)]
    return str(pathlib.Path(path).stem)

# Get filename extension
def GetFilenameExtension(path):
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if path.endswith(tarball_ext):
            return tarball_ext
    return pathlib.Path(path).suffix

# Get filename anchor
def GetFilenameAnchor(path):
    if path.startswith(config.drive_root_posix):
        return str(pathlib.PurePosixPath(path).anchor)
    else:
        return str(pathlib.PureWindowsPath(path).anchor)

# Get filename drive
def GetFilenameDrive(path):
    anchor = GetFilenameAnchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Get filename drive offset
def GetFilenameDriveOffset(path):
    anchor = GetFilenameAnchor(path)
    if len(anchor) == 0:
        return path
    return path[len(anchor):]

# Get filename front slice
def GetFilenameFrontSlice(path):
    return RebaseFilePath(path, GetFilenameFront(path) + config.os_pathsep, "")

# Get filename file
def GetFilenameFile(path):
    return GetFilenameBasename(path) + GetFilenameExtension(path)

# Get file size
def GetFileSize(path):
    return os.path.getsize(path)

# Get file mime type
def GetFileMimeType(path):
    try:
        import magic
        return magic.from_file(path, mime=True)
    except:
        pass
    return ""

# Get filename info
def GetFilenameInfo(path):
    info = {}
    info["orig"] = path
    info["parts"] = GetFilenameParts(path)
    info["dir"] = GetFilenameDirectory(path)
    info["front"] = GetFilenameFront(path)
    info["file_split"] = GetFilenameSplit(path)
    info["file_base"] = GetFilenameBasename(path)
    info["file_ext"] = GetFilenameExtension(path)
    info["file_anchor"] = GetFilenameAnchor(path)
    info["file_drive"] = GetFilenameDrive(path)
    info["file_drive_offset"] = GetFilenameDriveOffset(path)
    info["file"] = GetFilenameFile(path)
    info["size"] = GetFileSize(path)
    info["mime"] = GetFileMimeType(path)
    return info

###########################################################

# Get link info
def GetLinkInfo(lnk_path, lnk_base_path):

    # Import pylnk
    environment.ImportPythonModuleFile(
        module_path = programs.GetToolProgram("PyLnk"),
        module_name = "pylnk")

    # Link info
    info = {}
    info["target"] = ""
    info["cwd"] = ""
    info["args"] = []

    # Check params
    if not IsPathValid(lnk_path) or not os.path.isfile(lnk_path) or not lnk_path.endswith(".lnk"):
        return info
    if not IsPathValid(lnk_base_path) or not os.path.isdir(lnk_base_path):
        return info

    # Parse link file
    try:
        lnk = pylnk.Lnk(lnk_path)
        has_full_path = lnk._link_info
        has_relative_path = lnk.link_flags.HasRelativePath
        has_working_dir = lnk.link_flags.HasWorkingDir
        has_arguments = lnk.link_flags.HasArguments
        if has_full_path:

            # Get start path
            lnk_start_path = NormalizeFilePath(GetFilenameDirectory(lnk_path))

            # Get full path
            lnk_full_path = NormalizeFilePath(lnk._link_info.path)
            lnk_offset_path = GetFilenameDriveOffset(lnk_full_path)

            # Get relative path
            lnk_relative_path = ""
            if has_relative_path:
                lnk_relative_path = NormalizeFilePath(lnk.relative_path)
            else:
                lnk_relative_path = GetFilenameFile(lnk_full_path)

            # Get working dir
            lnk_working_dir = "."
            if has_working_dir:
                lnk_working_dir = NormalizeFilePath(lnk.work_dir)

            # Get arguments
            lnk_arguments = []
            if has_arguments:
                lnk_arguments = SplitByEnclosedSubstrings(lnk.arguments.strip("\x00"), "\"", "\"")

            # Get target
            lnk_target = NormalizeFilePath(os.path.join(lnk_base_path, lnk_offset_path))

            # Get cwd
            lnk_cwd = ""
            if ntpath.isabs(lnk_working_dir):
                lnk_cwd = NormalizeFilePath(os.path.join(lnk_base_path, GetDirectoryDriveOffset(lnk_working_dir)))
            else:
                lnk_cwd = NormalizeFilePath(os.path.join(GetFilenameDirectory(lnk_target), lnk_working_dir))

            # Get info
            info["target"] = lnk_target
            info["cwd"] = lnk_cwd
            info["args"] = lnk_arguments
    except Exception as e:
        LogError(e)
    return info

###########################################################
