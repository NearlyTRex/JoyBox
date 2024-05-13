# Imports
import os, os.path
import re
import stat
import sys
import errno
import stat
import shutil
import tempfile
import pathlib
import posixpath
import ntpath
import glob
import json

# Local imports
import config
import environment
import hashing
import programs

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
def PromptForIntegerValue(description, default_value):
    value = PromptForValue(description, default_value)
    try:
        return int(value)
    except:
        return default_value

###########################################################

# Get enclosed substrings from a delimiter
def FindEnclosedSubstrings(string, delimiter = "\""):
    pattern = "([%s])(?:\\?.)*?\1" % delimiter
    return re.findall(pattern, string)

# Get string similarity ratio
def GetStringSimilarityRatio(string1, string2):
    try:
        from thefuzz import fuzz
        return fuzz.ratio(string1, string2)
    except:
        return 0

# Split by enclosed substrings
def SplitByEnclosedSubstrings(string, delimiter = "\""):
    string_list = []
    enclosed_substrings = FindEnclosedSubstrings(string, delimiter)
    for string_segment in string.strip().split(delimiter):
        string_segment_enclosed = delimiter + string_segment + delimiter
        if string_segment_enclosed in enclosed_substrings:
            string_list.append(string_segment)
        else:
            string_list += string_segment.strip().split()
    return string_list

###########################################################

# Log message
def Log(message):
    try:
        print(message)
    except UnicodeEncodeError:
        print(message.encode("utf-8", "ignore").decode("utf-8"))
    except:
        pass

# Log colored
def LogColored(message, color = None, on_color = None, attrs = None):
    try:
        import termcolor
        if environment.IsWindowsPlatform():
            import colorama
            colorama.just_fix_windows_console()
        termcolor.cprint(message, color, on_color, attrs)
    except:
        Log(message)

# Log colored with header
def LogColoredWithHeader(message, header, color):
    try:
        import termcolor
        if environment.IsWindowsPlatform():
            import colorama
            colorama.just_fix_windows_console()
        Log(termcolor.colored("%s:" % header, color) + " " + message)
    except:
        Log("%s: " % header + message)

# Log info
def LogInfo(message):
    LogColoredWithHeader(str(message), "INFO", "light_blue")

# Log warning
def LogWarning(message):
    LogColoredWithHeader(str(message), "WARNING", "yellow")

# Log error
def LogError(message):
    LogColoredWithHeader(str(message), "ERROR", "red")

# Log success
def LogSuccess(message):
    LogColoredWithHeader(str(message), "SUCCESS", "green")

# Log percent complete
def LogPercentComplete(percent_complete):
    print(">>> Percent complete: %s%% " % percent_complete, end='\r', flush=True)

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

# Check if path exists
def DoesPathExist(path, case_sensitive_paths = True, partial_paths = False):
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

# Check if drive letter is valid
def IsDriveLetterValid(drive_letter):
    if not drive_letter or not isinstance(drive_letter, str) or len(drive_letter) == 0:
        return False
    return drive_letter.isalpha()

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
                Log("Path %s is not a file" % src)
            return False
        if verbose:
            Log("Replacing lines in file %s" % src)
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
            sys.exit(1)
        return False

# Append line to file
def AppendLineToFile(src, line, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                Log("Path %s is not a file" % src)
            return False
        if verbose:
            Log("Adding line '%s' to file %s" % (line, src))
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
            sys.exit(1)
        return False

# Sort file contents
def SortFileContents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                Log("Path %s is not a file" % src)
            return False
        if verbose:
            Log("Sorting contents of file %s" % src)
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
            sys.exit(1)
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
            Log("Lowercasing all paths in directory %s" % dir)
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
            sys.exit(1)

###########################################################

# Touch file
def TouchFile(src, contents = "", contents_mode = "w", encoding = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Touching file %s" % src)
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
            sys.exit(1)
        return False

# Chmod file or directory
def ChmodFileOrDirectory(src, perms, dperms = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Changing permissions of %s to %s" % (src, str(perms)))
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
            sys.exit(1)
        return False

# Mark as executable
def MarkAsExecutable(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Marking %s as executable" % src)
        if not pretend_run:
            st = os.stat(src)
            os.chmod(src, st.st_mode | stat.S_IEXEC)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to mark %s as executable" % src)
            LogError(e)
            sys.exit(1)
        return False

# Create temporary directory
def CreateTemporaryDirectory(verbose = False, pretend_run = False):
    if verbose:
        Log("Creating temporary directory")
    dir = ""
    if not pretend_run:
        dir = os.path.realpath(tempfile.mkdtemp())
        if verbose:
            Log("Created temporary directory %s" % dir)
    if not os.path.isdir(dir):
        return (False, "Unable to create temporary directory")
    return (True, dir)

# Create symlink
def CreateSymlink(src, dest, cwd = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Creating symlink from %s to %s" % (src, dest))
        if not pretend_run:
            if cwd:
                os.chdir(cwd)
            os.symlink(src, dest, target_is_directory = os.path.isdir(src))
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to create symlink from %s to %s" % (src, dest))
            LogError(e)
            sys.exit(1)
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
            Log("Copying %s to %s" % (src, dest))
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
            sys.exit(1)
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
            Log("Moving %s to %s" % (src, dest))
        if not pretend_run:
            shutil.move(src, dest)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to move %s to %s" % (src, dest))
            LogError(e)
            sys.exit(1)
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
            Log("Transferring %s to %s" % (src, dest))
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
            sys.exit(1)
        return False

# Make directory
def MakeDirectory(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isdir(dir):
            if verbose:
                Log("Making directory %s" % dir)
            if not pretend_run:
                os.makedirs(dir)
        return True
    except Exception as e:
        if not os.path.isdir(dir):
            if exit_on_failure:
                LogError("Unable to make directory %s" % dir)
                LogError(e)
                sys.exit(1)
            return False
        return True

# Remove file
def RemoveFile(file, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Removing file %s" % file)
        if not pretend_run:
            if os.path.isfile(file):
                os.remove(file)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove file %s" % file)
            LogError(e)
            sys.exit(1)
        return False

# Remove symlink
def RemoveSymlink(symlink, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Removing symlink %s" % symlink)
        if not pretend_run:
            if os.path.islink(symlink):
                os.unlink(symlink)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove symlink %s" % symlink)
            LogError(e)
            sys.exit(1)
        return False

# Remove directory
def RemoveDirectory(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Removing directory %s" % dir)
        if not pretend_run:
            if os.path.isdir(dir):
                shutil.rmtree(dir)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to remove directory %s" % dir)
            LogError(e)
            sys.exit(1)
        return False

# Remove directory contents
def RemoveDirectoryContents(dir, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            Log("Removing contents of directory %s" % dir)
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
            sys.exit(1)
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not DoesPathExist(src, case_sensitive_paths):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot copy" % src)
            sys.exit(1)
    file_list = BuildFileList(src, use_relative_paths = True)
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
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not DoesPathExist(src, case_sensitive_paths):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot move" % src)
            sys.exit(1)
    file_list = BuildFileList(src, use_relative_paths = True)
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

# Sync contents
def SyncContents(src, dest, verbose = False, pretend_run = False, exit_on_failure = False):
    if not DoesPathExist(src):
        if exit_on_failure:
            LogError("Source %s does not exist, cannot sync" % src)
            sys.exit(1)
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
def ReadJsonFile(src, verbose = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return {}
        if verbose:
            Log("Reading %s" % src)
        json_data = {}
        with open(src, "r") as input_file:
            file_contents = input_file.read()
            json_data = json.loads(file_contents)
        return json_data
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to read %s" % src)
            LogError(e)
            sys.exit(1)
        return {}

# Write json file
def WriteJsonFile(src, json_data, sort_keys = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            Log("Writing %s" % src)
        if not pretend_run:
            with open(src, "w", newline='\n') as output_file:
                json_string = json.dumps(json_data, indent = 4, sort_keys = sort_keys)
                output_file.write(json_string)
        return True
    except Exception as e:
        if exit_on_failure:
            LogError("Unable to write %s" % src)
            LogError(e)
            sys.exit(1)
        return False

# Clean json file
def CleanJsonFile(src, sort_keys = False, remove_empty_values = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not src.endswith(".json"):
            return False
        if verbose:
            Log("Cleaning %s" % src)
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
            sys.exit(1)
        return False

###########################################################

# Build file list
def BuildFileList(root, new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
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
    return sorted(files)

# Build file list by extensions
def BuildFileListByExtensions(root, extensions = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    files = []
    for file in BuildFileList(root, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs):
        base, ext = GetFilenameSplit(file)
        if isinstance(extensions, list) and len(extensions) > 0:
            if ext in extensions or ext.lower() in extensions or ext.upper() in extensions:
                files.append(file)
        else:
            files.append(file)
    return sorted(files)

# Build directory list
def BuildDirectoryList(root, new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    directories = []
    if not IsPathValid(root):
        return directories
    absolute_root = os.path.abspath(root)
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
    return sorted(directories)

# Build empty directory list
def BuildEmptyDirectoryList(root, new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in BuildDirectoryList(root, new_relative_path, use_relative_paths):
        if IsDirectoryEmpty(potential_dir):
            directories.append(potential_dir)
    return directories

# Build symlink directory list
def BuildSymlinkDirectoryList(root, new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in BuildDirectoryList(root, new_relative_path, use_relative_paths):
        if os.path.islink(potential_dir):
            directories.append(potential_dir)
    return directories

###########################################################

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
    return relative_file_list

# Convert file list to absolute paths
def ConvertFileListToAbsolutePaths(file_list, base_dir):
    absolute_file_list = []
    for filename in file_list:
        absolute_file_list.append(os.path.join(base_dir, filename))
    return absolute_file_list

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
def GetDirectoryContents(path):
    contents = []
    if DoesPathExist(path):
        contents = os.listdir(path)
    return sorted(contents)

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
def DoesDirectoryContainFiles(path):
    return len(BuildFileList(path)) > 0

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
    for tarball_ext in config.computer_archive_extensions_tarball:
        if path.endswith(tarball_ext):
            path = path[:-len(tarball_ext.replace(".", ""))]
    return str(pathlib.Path(path).stem)

# Get filename extension
def GetFilenameExtension(path):
    for tarball_ext in config.computer_archive_extensions_tarball:
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
    environment.ImportPythonModule(
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
                lnk_arguments = SplitByEnclosedSubstrings(lnk.arguments.strip("\x00"), delimiter = "\"")

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
