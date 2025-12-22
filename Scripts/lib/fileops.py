# Imports
import os
import stat
import shutil
import tempfile
import errno
import glob
import ntpath

# Local imports
import config
import hashing
import logger
import modules
import paths
import programs
import strings
import system

###########################################################
# File checking utilities
###########################################################

# Determine if file is correctly headered
def is_file_correctly_headered(src, expected_header):
    if os.path.isfile(src):
        with open(src, "rb") as file:
            actual_header = file.read(len(expected_header))
            if isinstance(expected_header, bytes):
                return (actual_header == expected_header)
            elif isinstance(expected_header, str):
                return (actual_header == bytes(expected_header, "utf-8"))
    return False

###########################################################
# File content modification utilities
###########################################################

# Replace strings in file
def replace_strings_in_file(src, replacements = [], verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                logger.log_info("Path %s is not a file" % src)
            return False
        if verbose:
            logger.log_info("Replacing lines in file %s" % src)
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
            logger.log_error("Unable to replace strings in file %s" % src)
            logger.log_error(e)
            system.QuitProgram()
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
            logger.log_error("Unable to add line '%s' to file %s" % (line, src))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Sort file contents
def sort_file_contents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if not os.path.isfile(src):
            if verbose:
                logger.log_info("Path %s is not a file" % src)
            return False
        if verbose:
            logger.log_info("Sorting contents of file %s" % src)
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
            logger.log_error("Unable to sort contents of file %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

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
        def onFoundItems(root, items):
            for name in items:
                if not pretend_run:
                    before = os.path.join(root, name)
                    after = os.path.join(root, name.lower())
                    if before != after:
                        os.rename(before, after)
        for root, dirs, files in os.walk(src, topdown = False):
            onFoundItems(root, dirs)
            onFoundItems(root, files)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to lowercase directory %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

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

# Touch file
def touch_file(src, contents = "", contents_mode = "w", encoding = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Touching file %s" % src)
        if not pretend_run:
            os.makedirs(paths.get_filename_directory(src), exist_ok = True)
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
            logger.log_error("Unable to touch file %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Chmod file or directory
def chmod_file_or_directory(src, perms, dperms = None, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Changing permissions of %s to %s" % (src, str(perms)))
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
            logger.log_error("Unable to change permissions of %s to %s" % (src, str(perms)))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Mark as executable
def mark_as_executable(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Marking %s as executable" % src)
        if not pretend_run:
            st = os.stat(src)
            os.chmod(src, st.st_mode | stat.S_IEXEC)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to mark %s as executable" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Create temporary directory
def create_temporary_directory(verbose = False, pretend_run = False):
    if verbose:
        logger.log_info("Creating temporary directory")
    temp_dir = ""
    if not pretend_run:
        temp_dir = os.path.realpath(tempfile.mkdtemp())
        if verbose:
            logger.log_info("Created temporary directory %s" % temp_dir)
    if not os.path.isdir(temp_dir):
        return (False, "Unable to create temporary directory")
    return (True, temp_dir)

# Create temporary file
def create_temporary_file(suffix = "", verbose = False, pretend_run = False):
    if verbose:
        logger.log_info("Creating temporary file")
    temp_file = ""
    if not pretend_run:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            temp_file = tf.name
        if verbose:
            logger.log_info("Created temporary file %s" % temp_file)
    return temp_file

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
    try:
        if verbose:
            logger.log_info("Creating symlink from %s to %s" % (src, dest))
        if not pretend_run:
            if cwd:
                os.chdir(cwd)
            if make_parent:
                parent_dir = os.path.dirname(dest)
                if parent_dir:
                    if verbose:
                        logger.log_info("Making parent dir %s" % parent_dir)
                    os.makedirs(parent_dir, exist_ok = True)
            if overwrite:
                if verbose:
                    logger.log_info("Removing destination %s first" % dest)
                if os.path.islink(dest):
                    os.unlink(dest)
                elif os.path.isfile(dest):
                    os.remove(dest)
                elif os.path.isdir(dest):
                    shutil.rmtree(dest)
            os.symlink(src, dest, target_is_directory = os.path.isdir(src))
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to create symlink from %s to %s" % (src, dest))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Resolve symlink
def resolve_symlink(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Resolving symlink %s" % src)
        if not pretend_run:
            if os.path.islink(src):
                return os.path.realpath(src)
        return None
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to resolve symlink %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return None

###########################################################
# File and directory copy/move utilities
###########################################################

# Copy file or directory
def copy_file_or_directory(
    src,
    dest,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if skip_existing and paths.does_path_exist(dest, case_sensitive_paths):
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
            logger.log_info("Copying %s to %s" % (src, dest))
        if not pretend_run:
            if os.path.isdir(src):
                shutil.copytree(src, dest, dirs_exist_ok=True)
            else:
                shutil.copy(src, dest)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to copy %s to %s" % (src, dest))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Move file or directory
def move_file_or_directory(
    src,
    dest,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        if skip_existing and paths.does_path_exist(dest, case_sensitive_paths):
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
            logger.log_info("Moving %s to %s" % (src, dest))
        if not pretend_run:
            shutil.move(src, dest)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to move %s to %s" % (src, dest))
            logger.log_error(e)
            system.QuitProgram()
        return False

# Transfer file
def transfer_file(
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
        if skip_existing and paths.does_path_exist(dest, case_sensitive_paths):
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
            logger.log_info("Transferring %s to %s" % (src, dest))
        if not pretend_run:
            total_size = paths.get_file_size(src)
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
            logger.log_error("Unable to transfer %s to %s" % (src, dest))
            logger.log_error(e)
            system.QuitProgram()
        return False

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
    except Exception as e:
        if not os.path.isdir(src):
            if exit_on_failure:
                logger.log_error("Unable to make directory %s" % src)
                logger.log_error(e)
                system.QuitProgram()
            return False
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
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to remove file %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Remove symlink
def remove_symlink(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing symlink %s" % src)
        if not pretend_run:
            if os.path.islink(src):
                os.unlink(src)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to remove symlink %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Remove directory
def remove_directory(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing directory %s" % src)
        if not pretend_run:
            if os.path.isdir(src):
                shutil.rmtree(src)
        return True
    except Exception as e:
        if exit_on_failure:
            logger.log_error("Unable to remove directory %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

# Remove directory contents
def remove_directory_contents(src, verbose = False, pretend_run = False, exit_on_failure = False):
    try:
        if verbose:
            logger.log_info("Removing contents of directory %s" % src)
        if not pretend_run:
            for root, dirs, files in os.walk(src):
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
            logger.log_error("Unable to remove contents of directory %s" % src)
            logger.log_error(e)
            system.QuitProgram()
        return False

###########################################################
# Bulk copy/move utilities
###########################################################

# Copy contents
def copy_contents(
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
    if not paths.does_path_exist(src, case_sensitive_paths):
        if exit_on_failure:
            logger.log_error("Source %s does not exist, cannot copy" % src)
            system.QuitProgram()
    file_list = paths.build_file_list(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = transfer_file(
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
def move_contents(
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
    if not paths.does_path_exist(src, case_sensitive_paths):
        if exit_on_failure:
            logger.log_error("Source %s does not exist, cannot move" % src)
            system.QuitProgram()
    file_list = paths.build_file_list(
        root = src,
        use_relative_paths = True,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs)
    for file in file_list:
        input_file = os.path.join(src, file)
        output_file = os.path.join(dest, file)
        output_dir = os.path.dirname(output_file)
        success = make_directory(
            src = output_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = transfer_file(
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
def copy_globbed_files(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    glob_source_dir = paths.get_filename_directory(glob_pattern)
    glob_files = paths.convert_file_list_to_relative_paths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    for glob_file in glob_files:
        success = make_directory(
            src = os.path.join(dest_dir, paths.get_filename_directory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = transfer_file(
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
def move_globbed_files(
    glob_pattern,
    dest_dir,
    show_progress = False,
    skip_existing = False,
    skip_identical = False,
    case_sensitive_paths = True,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    glob_source_dir = paths.get_filename_directory(glob_pattern)
    glob_files = paths.convert_file_list_to_relative_paths(
        file_list = glob.glob(glob_pattern),
        base_dir = glob_source_dir)
    for glob_file in glob_files:
        success = make_directory(
            src = os.path.join(dest_dir, paths.get_filename_directory(glob_file)),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        success = transfer_file(
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

###########################################################
# Smart copy/move utilities
###########################################################

# Smart copy
def smart_copy(
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
    success = make_directory(
        src = paths.get_filename_directory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.token_glob in paths.get_filename_basename(src):
        return copy_globbed_files(
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
            return copy_contents(
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
            return transfer_file(
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
def smart_move(
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
    success = make_directory(
        src = paths.get_filename_directory(dest),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    if config.token_glob in paths.get_filename_basename(src):
        return move_globbed_files(
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
            return move_contents(
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
            return transfer_file(
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
def smart_transfer(
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
        return smart_move(
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
        return smart_copy(
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

###########################################################
# Sync utilities
###########################################################

# Sync contents
def sync_contents(
    src,
    dest,
    ignore_symlinks = False,
    follow_symlink_dirs = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if not paths.does_path_exist(src):
        if exit_on_failure:
            logger.log_error("Source %s does not exist, cannot sync" % src)
            system.QuitProgram()
    success = make_directory(
        src = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    success = remove_directory_contents(
        src = dest,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False
    return copy_contents(
        src = src,
        dest = dest,
        ignore_symlinks = ignore_symlinks,
        follow_symlink_dirs = follow_symlink_dirs,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Sync data
def sync_data(data_src, data_dest, verbose = False, pretend_run = False, exit_on_failure = False):
    is_glob_src = (config.token_glob in paths.get_filename_basename(data_src))
    is_glob_dest = (config.token_glob in paths.get_filename_basename(data_dest))
    if is_glob_src and is_glob_dest:
        return copy_globbed_files(
            glob_pattern = data_src,
            dest_dir = os.path.dirname(data_dest),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isdir(data_src):
        return sync_contents(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isfile(data_src):
        return smart_copy(
            src = data_src,
            dest = data_dest,
            verbose = verbose,
            pretend_run = pretend_run)

# Remove object
def remove_object(obj, verbose = False, pretend_run = False, exit_on_failure = False):
    if os.path.isfile(obj):
        return remove_file(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.islink(obj):
        return remove_symlink(
            src = obj,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif os.path.isdir(obj):
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
# Link info utilities
###########################################################

# Get link info
def get_link_info(lnk_path, lnk_base_path):

    # Import pylnk
    pylnk = modules.import_python_module_file(
        module_path = programs.GetToolProgram("PyLnk"),
        module_name = "pylnk")

    # Link info
    info = {}
    info["target"] = ""
    info["cwd"] = ""
    info["args"] = []

    # Check params
    if not paths.is_path_valid(lnk_path) or not os.path.isfile(lnk_path) or not lnk_path.endswith(".lnk"):
        return info
    if not paths.is_path_valid(lnk_base_path) or not os.path.isdir(lnk_base_path):
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
            lnk_start_path = paths.normalize_file_path(paths.get_filename_directory(lnk_path))

            # Get full path
            lnk_full_path = paths.normalize_file_path(lnk._link_info.path)
            lnk_offset_path = paths.get_filename_drive_offset(lnk_full_path)

            # Get relative path
            lnk_relative_path = ""
            if has_relative_path:
                lnk_relative_path = paths.normalize_file_path(lnk.relative_path)
            else:
                lnk_relative_path = paths.get_filename_file(lnk_full_path)

            # Get working dir
            lnk_working_dir = "."
            if has_working_dir:
                lnk_working_dir = paths.normalize_file_path(lnk.work_dir)

            # Get arguments
            lnk_arguments = []
            if has_arguments:
                lnk_arguments = strings.split_by_enclosed_substrings(lnk.arguments.strip("\x00"), "\"", "\"")

            # Get target
            lnk_target = paths.normalize_file_path(os.path.join(lnk_base_path, lnk_offset_path))

            # Get cwd
            lnk_cwd = ""
            if ntpath.isabs(lnk_working_dir):
                lnk_cwd = paths.normalize_file_path(os.path.join(lnk_base_path, paths.get_directory_drive_offset(lnk_working_dir)))
            else:
                lnk_cwd = paths.normalize_file_path(os.path.join(paths.get_filename_directory(lnk_target), lnk_working_dir))

            # Get info
            info["target"] = lnk_target
            info["cwd"] = lnk_cwd
            info["args"] = lnk_arguments
    except Exception as e:
        logger.log_error(e)
    return info
