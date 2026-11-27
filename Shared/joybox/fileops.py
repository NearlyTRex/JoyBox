# Imports
import importlib
import os
import contextlib
import codecs
import stat
import struct
import time
import shutil
import tempfile
import glob
import fnmatch
import ntpath

# Local imports
from joybox import config
from joybox import hashutil
from joybox import logger
from joybox import modules
from joybox import paths
from joybox import platform_info
from joybox import runtime
from joybox import text
from joybox import programs

# Get tqdm, imported on first use
def _get_tqdm():
    return importlib.import_module("tqdm")

###########################################################
# Error handlers
###########################################################

# Report a file operation that failed, quitting when told to, and return False
def report_failure(message, error, exit_on_failure = False):
    if exit_on_failure:
        logger.log_error(message)
        logger.log_error(error)
        runtime.quit_program()
    return False

# Report a file a skip_on_error bulk copy or move could not handle, so a failing disk
# does not abort the run: remove its partial destination, so it does not pass for a
# success, and add the source to the error log when there is one
def report_fileio_error(src_path, dest_path = None, error_log_path = None, verbose = False, pretend_run = False):
    logger.log_warning("Skipping file after I/O error: '%s'" % src_path)
    if not pretend_run and dest_path and paths.does_path_exist(dest_path):
        remove_file(
            src = dest_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = False)
    if error_log_path:
        try:
            with open(error_log_path, "a", encoding = "utf-8") as f:
                f.write("%s\n" % src_path)
        except OSError as e:
            logger.log_warning("Unable to write error log '%s': %s" % (error_log_path, e))


###########################################################
# Directory modification utilities
###########################################################

# Remove empty directories
def remove_empty_directories(src, verbose = False, pretend_run = False, exit_on_failure = False):
    for empty_dir in paths.build_empty_directory_list(src):
        success = remove_directory(
            src = empty_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Replace symlinked directories
def replace_symlinked_directories(src, verbose = False, pretend_run = False, exit_on_failure = False):
    for symlink_dir in paths.build_symlink_directory_list(src):
        success = remove_symlink(
            src = symlink_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = make_directory(
            src = symlink_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Lowercase all paths
def lowercase_all_paths(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Lowercasing all paths in directory %s" % src)
        def on_found_items(root, items):
            for name in items:
                if not pretend_run:
                    before = os.path.join(root, name)
                    after = os.path.join(root, name.lower())
                    if before != after:
                        os.rename(before, after)
        for root, dirs, files in os.walk(src, topdown = False):
            on_found_items(root, dirs)
            on_found_items(root, files)
        return True
    except OSError as e:
        return report_failure("Unable to lowercase directory %s" % src, e, exit_on_failure)

# Whether a name is valid utf-8, rather than holding undecodable bytes
def is_utf8_name(name):
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True

# Determine if a name stops partway through a character of a legacy encoding
def is_name_split_in_encoding(name, encoding):
    if is_utf8_name(name):
        return False
    decoder = codecs.getincrementaldecoder(encoding)()
    try:
        decoder.decode(os.fsencode(name), final = False)
    except UnicodeDecodeError:
        return False
    try:
        decoder.decode(b"", final = True)
        return False
    except UnicodeDecodeError:
        return True

# Move a split directory's children up beside it, each rejoined to its name with a backslash
# unless that name is taken, returning whether the emptied directory was removed
def rejoin_split_directory(root, name, verbose = False, pretend_run = False):
    path = os.path.join(root, name)
    for child in os.listdir(path):
        after = os.path.join(root, name + "\\" + child)
        if os.path.exists(after):
            continue
        if verbose:
            logger.log_info("Rejoining %s to %s" % (os.path.join(path, child), after))
        if not pretend_run:
            os.rename(os.path.join(path, child), after)
    if pretend_run or os.listdir(path):
        return False
    os.rmdir(path)
    return True

# Rejoin names split where a character's second byte was read as a backslash
def rejoin_split_names(root, encoding, verbose = False, pretend_run = False):
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name)
        if not os.path.isdir(path) or os.path.islink(path):
            continue
        if not is_name_split_in_encoding(name, encoding):
            rejoin_split_names(path, encoding, verbose, pretend_run)
        elif rejoin_split_directory(root, name, verbose, pretend_run):
            rejoin_split_names(root, encoding, verbose, pretend_run)
            return

# Get a name that is not utf-8 decoded from a legacy encoding, or None when it is utf-8 or undecodable
def get_legacy_decoded_name(name, encoding):
    if is_utf8_name(name):
        return None
    try:
        return os.fsencode(name).decode(encoding)
    except UnicodeDecodeError:
        return None

# Rename names in a directory that are not utf-8 to their legacy decoding, unless that name is taken
def decode_legacy_names(root, names, encoding, verbose = False, pretend_run = False):
    for name in names:
        decoded_name = get_legacy_decoded_name(name, encoding)
        if not decoded_name:
            continue
        before = os.path.join(root, name)
        after = os.path.join(root, decoded_name)
        if os.path.exists(after):
            continue
        if verbose:
            logger.log_info("Renaming %s to %s" % (before, after))
        if not pretend_run:
            os.rename(before, after)

# Decode names that are not utf-8 from a legacy encoding
def decode_legacy_filenames(src, encoding, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Decoding %s paths in directory %s" % (encoding, src))
        rejoin_split_names(src, encoding, verbose, pretend_run)
        for root, dirs, files in os.walk(src, topdown = False):
            decode_legacy_names(root, dirs, encoding, verbose, pretend_run)
            decode_legacy_names(root, files, encoding, verbose, pretend_run)
        return True
    except OSError as e:
        return report_failure("Unable to decode paths in directory %s" % src, e, exit_on_failure)

# Sanitize filenames
def sanitize_filenames(path, extension = None, verbose = False, pretend_run = False, exit_on_failure = False):
    for obj in paths.get_directory_contents(path):
        obj_path = paths.join_paths(path, obj)
        if paths.is_path_file(obj_path):
            if extension and not obj.endswith(extension):
                continue
            success = move_file_or_directory(
                src = obj_path,
                dest = paths.join_paths(path, paths.replace_invalid_path_characters(obj)),
                skip_existing = True,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
    return True

###########################################################
# File and directory creation utilities
###########################################################

# Open a file only its owner can read
def open_private_file(src, contents_mode, encoding):
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
    flags |= os.O_APPEND if "a" in contents_mode else os.O_TRUNC
    descriptor = os.open(src, flags, 0o600)
    try:
        os.chmod(src, 0o600)
    except OSError:
        os.close(descriptor)
        raise
    return os.fdopen(descriptor, contents_mode, encoding = encoding)

# Write contents to a file, text in the encoding given or utf-8, and only its owner able to read it when private
def write_file_contents(src, contents, contents_mode = "w", encoding = None, private = False):
    text_encoding = None if "b" in contents_mode else (encoding or "utf-8")
    if private:
        handle = open_private_file(src, contents_mode, text_encoding)
    else:
        handle = open(src, contents_mode, encoding = text_encoding)
    with handle as f:
        f.write(contents)

# Touch file
def touch_file(src, contents = "", contents_mode = "w", encoding = None, private = False, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Touching file %s" % src)
        if pretend_run:
            return True
        os.makedirs(paths.get_filename_directory(src), exist_ok = True)
        if contents:
            write_file_contents(src, contents, contents_mode, encoding, private)
        else:
            with open(src, "a", encoding = "utf-8"):
                pass
        return True
    except (OSError, ValueError) as e:
        return report_failure("Unable to touch file %s" % src, e, exit_on_failure)

# Change a directory's permissions and those of everything under it, directories to dperms when given
def chmod_directory_tree(src, perms, dperms = None):
    file_mode = int(str(perms), base = 8)
    dir_mode = int(str(dperms or perms), base = 8)
    os.chmod(src, dir_mode)
    for root, dirs, files in os.walk(src):
        for f in files:
            os.chmod(os.path.join(root, f), file_mode)
        for d in dirs:
            os.chmod(os.path.join(root, d), dir_mode)

# Chmod file or directory
def chmod_file_or_directory(src, perms, dperms = None, verbose = False, pretend_run = False, exit_on_failure = False):
    message = "Unable to change permissions of %s to %s" % (src, str(perms))
    try:
        if verbose:
            logger.log_info("Changing permissions of %s to %s" % (src, str(perms)))
        if pretend_run:
            return True
        if not os.path.exists(src):
            return report_failure(message, "Path does not exist", exit_on_failure)
        if os.path.isfile(src):
            os.chmod(src, int(str(perms), base = 8))
        elif os.path.isdir(src):
            chmod_directory_tree(src, perms, dperms)
        return True
    except (OSError, ValueError) as e:
        return report_failure(message, e, exit_on_failure)

# Set file modified time
def set_file_modified_time(src, timestamp, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Setting modified time of %s to %s" % (src, str(timestamp)))
        if not pretend_run:
            os.utime(src, (timestamp, timestamp))
        return True
    except OSError as e:
        return report_failure("Unable to set modified time of %s" % src, e, exit_on_failure)

# Mark as executable
def mark_as_executable(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Marking %s as executable" % src)
        if not pretend_run:
            st = os.stat(src)
            os.chmod(src, st.st_mode | stat.S_IEXEC)
        return True
    except OSError as e:
        return report_failure("Unable to mark %s as executable" % src, e, exit_on_failure)

# Create temporary directory
def create_temporary_directory(directory = None, verbose = False, pretend_run = False):
    if verbose:
        logger.log_info("Creating temporary directory")
    # A pretend run gets the path it would have used, so it can carry on
    if pretend_run:
        return (True, os.path.join(directory or tempfile.gettempdir(), "pretend"))
    if directory:
        make_directory(src = directory)
        temp_dir = os.path.realpath(tempfile.mkdtemp(dir = directory))
    else:
        temp_dir = os.path.realpath(tempfile.mkdtemp())
    if verbose:
        logger.log_info("Created temporary directory %s" % temp_dir)
    if not os.path.isdir(temp_dir):
        return (False, "Unable to create temporary directory")
    return (True, temp_dir)

# Make a temporary directory for a with block, removing it afterwards. Yields its path,
# or None when it could not be made.
@contextlib.contextmanager
def temporary_directory(directory = None, verbose = False, pretend_run = False):
    success, temp_dir = create_temporary_directory(directory = directory, verbose = verbose, pretend_run = pretend_run)
    if not success:
        yield None
        return
    try:
        yield temp_dir
    finally:
        remove_directory(src = temp_dir, verbose = verbose, pretend_run = pretend_run, exit_on_failure = False)

# The directory given, left as it is, or else a temporary one removed afterwards. Yields
# None when a temporary one could not be made.
@contextlib.contextmanager
def existing_or_temporary_directory(existing_dir, verbose = False, pretend_run = False):
    with contextlib.ExitStack() as stack:
        if not existing_dir:
            existing_dir = stack.enter_context(temporary_directory(verbose = verbose, pretend_run = pretend_run))
        yield existing_dir

# Create temporary file
def create_temporary_file(suffix = "", prefix = "tmp", verbose = False, pretend_run = False):
    if verbose:
        logger.log_info("Creating temporary file")
    if pretend_run:
        return (True, os.path.join(tempfile.gettempdir(), prefix + "pretend" + suffix))
    with tempfile.NamedTemporaryFile(suffix=suffix, prefix=prefix, delete=False) as tf:
        temp_file = tf.name
    if verbose:
        logger.log_info("Created temporary file %s" % temp_file)
    if not os.path.isfile(temp_file):
        return (False, "Unable to create temporary file")
    return (True, temp_file)

# Get the working directory, or None when it no longer exists
def get_working_directory():
    try:
        return os.getcwd()
    except OSError:
        return None

# Make a path's parent directory, when it has one
def make_parent_directory(path, verbose = False):
    parent_dir = os.path.dirname(path)
    if parent_dir:
        if verbose:
            logger.log_info("Making parent dir %s" % parent_dir)
        os.makedirs(parent_dir, exist_ok = True)

# Remove whatever is at a path: a link, a file or a directory tree
def remove_existing_path(path):
    if os.path.islink(path):
        os.unlink(path)
    elif os.path.isfile(path):
        os.remove(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)

# Create symlink
def create_symlink(
    src,
    dest,
    cwd = None,
    overwrite = True,
    make_parent = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    prev_cwd = None
    try:
        if verbose:
            logger.log_info("Creating symlink from %s to %s" % (src, dest))
        if pretend_run:
            return True
        if cwd:
            prev_cwd = get_working_directory()
            os.chdir(cwd)
        if make_parent:
            make_parent_directory(dest, verbose)
        if overwrite:
            if verbose:
                logger.log_info("Removing destination %s first" % dest)
            remove_existing_path(dest)
        os.symlink(src, dest, target_is_directory = os.path.isdir(src))
        return True
    except OSError as e:
        return report_failure("Unable to create symlink from %s to %s" % (src, dest), e, exit_on_failure)
    finally:
        if prev_cwd is not None:
            os.chdir(prev_cwd)

# Determine if symlinks are supported
def are_symlinks_supported():
    if platform_info.is_unix_platform():
        return True
    test_file_src = paths.join_paths(os.path.expanduser("~"), ".symsrc")
    test_file_dest = paths.join_paths(os.path.expanduser("~"), ".symdest")
    if os.path.islink(test_file_dest):
        return True
    touch_file(test_file_src)
    create_symlink(test_file_src, test_file_dest)
    return os.path.islink(test_file_dest)

# Resolve symlink
def resolve_symlink(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Resolving symlink %s" % src)
        if not pretend_run:
            if os.path.islink(src):
                return os.path.realpath(src)
        return None
    except OSError as e:
        report_failure("Unable to resolve symlink %s" % src, e, exit_on_failure)
        return None

###########################################################
# File and directory copy/move utilities
###########################################################

# Get why a copy or move can skip its destination: "exists" when skipping existing ones,
# "identical" when skipping ones with the same contents, or None to go ahead
def get_skip_reason(src, dest, skip_existing = False, skip_identical = False, case_sensitive_paths = True, verbose = False, exit_on_failure = False):
    if skip_existing and paths.does_path_exist(dest, case_sensitive_paths):
        return "exists"
    if skip_identical and hashutil.are_files_identical(
        first = src,
        second = dest,
        case_sensitive_paths = case_sensitive_paths,
        verbose = verbose,
        exit_on_failure = exit_on_failure):
        return "identical"
    return None

# Report a copy or move that failed: as a skipped file when skipping on errors, else as a failure
def report_transfer_failure(message, error, src, dest, skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure):
    if skip_on_error:
        report_fileio_error(src, dest, error_log_path, verbose, pretend_run)
        return False
    return report_failure(message, error, exit_on_failure)

# Whether a name matches any of the fnmatch patterns given
def is_excluded_name(name, excludes):
    return any(fnmatch.fnmatch(name, pattern) for pattern in excludes or ())

# Get a copytree ignore function skipping names that match any of the patterns, or None without any
def get_exclude_ignore(excludes):
    if not excludes:
        return None
    return lambda _, names: {name for name in names if is_excluded_name(name, excludes)}

# Copy file or directory
# `excludes` is a list of fnmatch patterns; matching names are skipped (applied
# to directory member names, or to the basename when copying a single file).
def copy_file_or_directory(
    src,
    dest,
    excludes = (),
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        skip_reason = get_skip_reason(
            src, dest, skip_existing, skip_identical, case_sensitive_paths, verbose, exit_on_failure and not skip_on_error)
        if skip_reason:
            if verbose:
                logger.log_info("Skipping (%s): '%s'" % (skip_reason, dest))
            return True
        if verbose:
            logger.log_info("Copying: '%s' -> '%s'" % (src, dest))
        if pretend_run:
            return True
        if os.path.isdir(src):
            shutil.copytree(src, dest, ignore = get_exclude_ignore(excludes), dirs_exist_ok = True)
        elif not is_excluded_name(os.path.basename(src), excludes):
            shutil.copy(src, dest)
        return True
    except OSError as e:
        return report_transfer_failure(
            "Unable to copy %s to %s" % (src, dest), e,
            src, dest, skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure)

# Move file or directory
def move_file_or_directory(
    src,
    dest,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if get_skip_reason(
            src, dest, skip_existing, skip_identical, case_sensitive_paths, verbose, exit_on_failure and not skip_on_error):
            return True
        if verbose:
            logger.log_info("Moving %s to %s" % (src, dest))
        if not pretend_run:
            shutil.move(src, dest)
        return True
    except OSError as e:
        return report_transfer_failure(
            "Unable to move %s to %s" % (src, dest), e,
            src, dest, skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure)

# Copy a file's contents from one open file to another in chunks, updating a progress bar when there is one
def copy_file_chunks(fsrc, fdest, progress_bar = None):
    for buf in iter(lambda: fsrc.read(config.TRANSFER_CHUNK_SIZE), b""):
        fdest.write(buf)
        if progress_bar:
            progress_bar.update(len(buf))

# Copy a file's contents across, with a progress bar when asked
def copy_file_contents(src, dest, show_progress = False):
    progress_bar = None
    if show_progress:
        tqdm = _get_tqdm()
        progress_bar = tqdm.tqdm(total = paths.get_file_size(src))
    try:
        with open(src, "rb") as fsrc, open(dest, "wb") as fdest:
            copy_file_chunks(fsrc, fdest, progress_bar)
    finally:
        if progress_bar:
            progress_bar.close()

# Transfer file
def transfer_file(
    src,
    dest,
    delete_afterwards = False,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    skip_on_error = False,
    error_log_path = None,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if os.path.abspath(src) == os.path.abspath(dest) or get_skip_reason(
            src, dest, skip_existing, skip_identical, case_sensitive_paths, verbose, exit_on_failure and not skip_on_error):
            return True
        if verbose:
            logger.log_info("Transferring %s to %s" % (src, dest))
        if not pretend_run:
            copy_file_contents(src, dest, show_progress)
            shutil.copymode(src, dest)
            if delete_afterwards:
                os.remove(src)
        return True
    except OSError as e:
        return report_transfer_failure(
            "Unable to transfer %s to %s" % (src, dest), e,
            src, dest, skip_on_error, error_log_path, verbose, pretend_run, exit_on_failure)

###########################################################
# Directory creation/removal utilities
###########################################################

# Make directory
def make_directory(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isdir(src):
            if verbose:
                logger.log_info("Making directory %s" % src)
            if not pretend_run:
                os.makedirs(src, exist_ok = True)
        return True
    except OSError as e:
        if not os.path.isdir(src):
            return report_failure("Unable to make directory %s" % src, e, exit_on_failure)
        return True

# Remove file
def remove_file(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing file %s" % src)
        if not pretend_run:
            if os.path.isfile(src):
                os.remove(src)
        return True
    except OSError as e:
        return report_failure("Unable to remove file %s" % src, e, exit_on_failure)

# Remove symlink
def remove_symlink(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing symlink %s" % src)
        if not pretend_run:
            if os.path.islink(src):
                os.unlink(src)
        return True
    except OSError as e:
        return report_failure("Unable to remove symlink %s" % src, e, exit_on_failure)

# Remove directory
def remove_directory(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing directory %s" % src)
        if not pretend_run:
            if os.path.isdir(src):
                shutil.rmtree(src)
        return True
    except OSError as e:
        return report_failure("Unable to remove directory %s" % src, e, exit_on_failure)

# Make a directory and the directories under it writable, leaving links alone
def make_directories_writable(dir_path):
    os.chmod(dir_path, stat.S_IRWXU)
    for sub_root, sub_dirs, _ in os.walk(dir_path):
        for sub_dir in sub_dirs:
            sub_path = os.path.join(sub_root, sub_dir)
            if not os.path.islink(sub_path):
                os.chmod(sub_path, stat.S_IRWXU)

# Remove an entry of a directory: a file or link unlinked, a directory tree removed, making its
# directories writable first when read-only ones block removal of what they hold
def remove_directory_entry(path):
    if os.path.islink(path) or not os.path.isdir(path):
        os.unlink(path)
        return
    try:
        shutil.rmtree(path)
    except PermissionError:
        make_directories_writable(path)
        shutil.rmtree(path)

# Remove directory contents
def remove_directory_contents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing contents of directory %s" % src)
        if not pretend_run and os.path.isdir(src):
            for name in os.listdir(src):
                remove_directory_entry(os.path.join(src, name))
        return True
    except OSError as e:
        return report_failure("Unable to remove contents of directory %s" % src, e, exit_on_failure)


# Remove object
# Remove a file or directory, expanding shell glob patterns in the source path.
# Each match is removed by type (file, symlink, or directory tree).
def remove_file_or_directory(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing %s" % src)
        if not pretend_run:
            for match in glob.glob(src):
                remove_object(
                    obj = match,
                    verbose = verbose,
                    pretend_run = pretend_run,
                    exit_on_failure = exit_on_failure)
        return True
    except OSError as e:
        return report_failure("Unable to remove %s" % src, e, exit_on_failure)

def remove_object(obj, verbose = False, pretend_run = False, exit_on_failure = False):
    if os.path.isfile(obj):
        return remove_file(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.islink(obj):
        return remove_symlink(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    if os.path.isdir(obj):
        success_contents = remove_directory_contents(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        success_dir = remove_directory(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        return success_contents and success_dir
    return False

###########################################################
# Recycle bin utilities
###########################################################

# Get a file's path within a recycle bin: relative to the recycle root when under it, else its name
def get_recycle_relative_path(src, recycle_root):
    abs_src = os.path.abspath(src)
    abs_root = os.path.abspath(recycle_root)
    if os.path.commonpath([abs_src, abs_root]) == abs_root:
        return os.path.relpath(abs_src, abs_root)
    return paths.get_filename_file(src)

# Get a recycle bin destination not yet taken, stamping the time onto one that is
def get_unused_recycle_path(dest_path):
    if not paths.does_path_exist(dest_path):
        return dest_path
    base, ext = os.path.splitext(dest_path)
    return "%s_%d%s" % (base, int(time.time()), ext)

# Move file to recycle bin instead of deleting
def recycle_file(
    src,
    recycle_root,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Skip files missing or already in the recycle bin
    if not paths.does_path_exist(src):
        if verbose:
            logger.log_info("File does not exist: %s" % src)
        return True
    rel_path = get_recycle_relative_path(src, recycle_root)
    if rel_path.split(os.sep)[0] == recycle_folder:
        if verbose:
            logger.log_info("File already in recycle bin: %s" % src)
        return True

    # Move the file into the recycle bin
    dest_path = get_unused_recycle_path(paths.join_paths(recycle_root, recycle_folder, rel_path))
    if verbose:
        logger.log_info("Recycling: %s -> %s" % (src, dest_path))
    make_directory(
        src = paths.get_filename_directory(dest_path),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return move_file_or_directory(
        src = src,
        dest = dest_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Empty recycle bin
def empty_recycle_bin(
    recycle_root,
    recycle_folder = ".recycle_bin",
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get recycle bin path
    recycle_bin_path = os.path.join(recycle_root, recycle_folder)
    if not paths.does_path_exist(recycle_bin_path):
        if verbose:
            logger.log_info("Recycle bin does not exist: %s" % recycle_bin_path)
        return True

    # Empty recycle bin contents
    if verbose:
        logger.log_info("Emptying recycle bin: %s" % recycle_bin_path)
    return remove_directory_contents(
        src = recycle_bin_path,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
# Link info utilities
###########################################################

# Get the target, working directory and arguments of a parsed link file with a full path, under a base path
def get_parsed_link_info(lnk, lnk_base_path):
    lnk_offset_path = paths.get_filename_drive_offset(paths.normalize_file_path(lnk.link_info.path))
    lnk_working_dir = "."
    if lnk.link_flags.HasWorkingDir:
        lnk_working_dir = paths.normalize_file_path(lnk.work_dir)
    lnk_arguments = []
    if lnk.link_flags.HasArguments:
        lnk_arguments = text.split_by_enclosed_substrings(lnk.arguments.strip("\x00"), "\"", "\"")
    lnk_target = paths.normalize_file_path(os.path.join(lnk_base_path, lnk_offset_path))
    if ntpath.isabs(lnk_working_dir):
        lnk_cwd = paths.normalize_file_path(os.path.join(lnk_base_path, paths.get_directory_drive_offset(lnk_working_dir)))
    else:
        lnk_cwd = paths.normalize_file_path(os.path.join(paths.get_filename_directory(lnk_target), lnk_working_dir))
    return {"target": lnk_target, "cwd": lnk_cwd, "args": lnk_arguments}

# Get link info
def get_link_info(lnk_path, lnk_base_path):
    pylnk = modules.import_python_module_file(
        module_path = programs.get_tool_program("PyLnk"),
        module_name = "pylnk")
    info = {"target": "", "cwd": "", "args": []}
    if not paths.is_path_valid(lnk_path) or not os.path.isfile(lnk_path) or not lnk_path.endswith(".lnk"):
        return info
    if not paths.is_path_valid(lnk_base_path) or not os.path.isdir(lnk_base_path):
        return info
    try:
        lnk = pylnk.Lnk(lnk_path)
        if lnk.link_info:
            info = get_parsed_link_info(lnk, lnk_base_path)
    except (OSError, ValueError, KeyError, struct.error, pylnk.FormatException) as e:
        logger.log_error(e)
    return info
