# Imports
import importlib
import os
import shutil
import errno
import fnmatch
import pathlib
import posixpath
import ntpath
import time

# Local imports
from joybox import config
from joybox import text
from joybox import strings

# Get magic, imported on first use
def _get_magic():
    return importlib.import_module("magic")

###########################################################
# Path checking and validation utilities
###########################################################

# Expand path (environment variables and ~)
def expand_path(path):
    return os.path.expandvars(os.path.expanduser(path))

# Check if path is the parent of another
def is_parent_path(parent_path, child_path):
    try:
        parent = pathlib.Path(parent_path).resolve()
        child = pathlib.Path(child_path).resolve()
        return child.is_relative_to(parent)
    except ValueError:
        return False

# Check if path exists
def does_path_exist(path, case_sensitive_paths = True, partial_paths = False):
    if not path:
        return False
    if case_sensitive_paths:
        return os.path.exists(path)
    path_parent = str(pathlib.Path(path).parent)
    path_name = str(pathlib.Path(path).name)
    if not os.path.isdir(path_parent):
        return False
    for obj in os.listdir(path_parent):
        if partial_paths and obj.startswith(path_name):
            return True
        if not partial_paths and path_name.lower() == obj.lower():
            return True
    return False

# Check if two paths point to the same location
def are_paths_equal(path1, path2):
    if not path1 or not path2:
        return False
    return os.path.realpath(path1) == os.path.realpath(path2)

# Check if path is a file
def is_path_file(path):
    if not is_path_valid(path):
        return False
    if not does_path_exist(path):
        return False
    return os.path.isfile(path)

# Check if path is a directory
def is_path_directory(path):
    if not is_path_valid(path):
        return False
    if not does_path_exist(path):
        return False
    return os.path.isdir(path)

# Check if path is a symlink
def is_path_symlink(path):
    if not is_path_valid(path):
        return False
    return os.path.islink(path)

# Check if path is an existing file or directory, following symlinks to either
def is_path_file_or_directory(path):
    if not is_path_valid(path):
        return False
    if not does_path_exist(path):
        return False
    return os.path.isfile(path) or os.path.isdir(path)

# Check if drive letter is valid
def is_drive_letter_valid(drive_letter):
    if not drive_letter or not isinstance(drive_letter, str) or len(drive_letter) == 0:
        return False
    return drive_letter.isalpha()

# Strip rich text and control characters, apply config.path_text_replacements, trim trailing dots and collapse spaces
def replace_invalid_path_characters(path):

    # Rich text
    new_path = text.clean_rich_text(path)

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
# Path list utilities
###########################################################

# Sorted, de-duplicated paths with any that start with an exclude prefix dropped
def prune_paths(paths, excludes = ()):
    new_paths = set()
    for path in paths:
        should_add = True
        for exclude in excludes:
            if path.startswith(exclude):
                should_add = False
        if should_add:
            new_paths.add(path)
    return strings.sort_strings(new_paths)

# Sorted paths with those nested under another listed path dropped; the bare install-dir token goes when a deeper one is listed
def prune_child_paths(paths):
    filtered_paths = list(paths)
    if config.TOKEN_GAME_INSTALL_DIR in filtered_paths:
        has_specific_install_paths = any(
            path.startswith(config.TOKEN_GAME_INSTALL_DIR + "/")
            for path in filtered_paths
        )
        if has_specific_install_paths:
            filtered_paths = [p for p in filtered_paths if p != config.TOKEN_GAME_INSTALL_DIR]
    new_paths = set()
    for path in strings.sort_strings(filtered_paths):
        if not any(is_parent_path(added_path, path) for added_path in new_paths):
            new_paths.add(path)
    return strings.sort_strings(new_paths)

# A listed location as is, or relative to absolute_root under new_relative_path when relative paths are asked for
def _format_listed_path(location, absolute_root, new_relative_path, use_relative_paths):
    if not use_relative_paths:
        return location
    if new_relative_path and not new_relative_path.endswith(config.OS_PATHSEP):
        new_relative_path += config.OS_PATHSEP
    return new_relative_path + os.path.relpath(location, absolute_root)

# Files in the directory tree at root, in walk order, formatted as build_file_list lists them
def _list_tree_files(root, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs):
    absolute_root = os.path.abspath(root)
    files = []
    for base, _, filenames in os.walk(root, followlinks = follow_symlink_dirs):
        for filename in filenames:
            location = os.path.abspath(os.path.join(base, filename))
            if ignore_symlinks and os.path.islink(location):
                continue
            files.append(_format_listed_path(location, absolute_root, new_relative_path, use_relative_paths))
    return files

# Sorted files under root, recursing, as absolute paths or relative ones under new_relative_path; empty for an invalid root
def build_file_list(root, excludes = None, new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    excludes = [] if excludes is None else excludes
    files = []
    if not is_path_valid(root):
        return files
    if os.path.isdir(root):
        files = _list_tree_files(root, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs)
    elif os.path.isfile(root):
        location = os.path.abspath(root)
        if not ignore_symlinks or not os.path.islink(location):
            files.append(location)
    return prune_paths(files, excludes)

# Files from build_file_list whose extension matches one listed, in any case; every file when none are listed
def build_file_list_by_extensions(root, excludes = None, extensions = None, new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    excludes = [] if excludes is None else excludes
    extensions = [] if extensions is None else extensions
    files = []
    for file in build_file_list(root, excludes, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs):
        _, ext = get_filename_split(file)
        if isinstance(extensions, list) and len(extensions) > 0:
            if ext in extensions or ext.lower() in extensions or ext.upper() in extensions:
                files.append(file)
        else:
            files.append(file)
    return strings.sort_strings(files)

# Sorted directories under root, root itself included, as absolute or relative paths; empty for an invalid root
def build_directory_list(root, excludes = None, new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    excludes = [] if excludes is None else excludes
    directories = []
    if not is_path_valid(root):
        return directories
    absolute_root = os.path.abspath(root)
    if os.path.isdir(absolute_root):
        directories.append(absolute_root)
    for base, dirnames, _ in os.walk(root, followlinks = follow_symlink_dirs):
        for dirname in dirnames:
            location = os.path.abspath(os.path.join(base, dirname))
            if ignore_symlinks and os.path.islink(location):
                continue
            directories.append(_format_listed_path(location, absolute_root, new_relative_path, use_relative_paths))
    return prune_paths(directories, excludes)

# Where a path build_directory_list listed sits on disk, undoing its relative form
def _locate_listed_path(root, listed_path, new_relative_path, use_relative_paths):
    if not use_relative_paths or os.path.isabs(listed_path):
        return listed_path
    if new_relative_path and not new_relative_path.endswith(config.OS_PATHSEP):
        new_relative_path += config.OS_PATHSEP
    return os.path.join(os.path.abspath(root), listed_path.removeprefix(new_relative_path))

# Directories from build_directory_list that hold nothing
def build_empty_directory_list(root, excludes = None, new_relative_path = "", use_relative_paths = False):
    excludes = [] if excludes is None else excludes
    directories = []
    for potential_dir in build_directory_list(root, excludes, new_relative_path, use_relative_paths):
        if is_directory_empty(_locate_listed_path(root, potential_dir, new_relative_path, use_relative_paths)):
            directories.append(potential_dir)
    return directories

# Directories from build_directory_list that are themselves symlinks
def build_symlink_directory_list(root, excludes = None, new_relative_path = "", use_relative_paths = False):
    excludes = [] if excludes is None else excludes
    directories = []
    for potential_dir in build_directory_list(root, excludes, new_relative_path, use_relative_paths):
        if os.path.islink(_locate_listed_path(root, potential_dir, new_relative_path, use_relative_paths)):
            directories.append(potential_dir)
    return directories

# Whether a relative path, or any leading part of it, matches one of the fnmatch exclude patterns
def matches_exclude_pattern(rel_path, excludes):
    for pattern in excludes:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        parts = rel_path.split(os.sep)
        for i in range(len(parts)):
            partial = os.sep.join(parts[:i+1])
            if fnmatch.fnmatch(partial, pattern.removesuffix("/**")):
                return True
    return False

# Subdirectory paths directly inside a directory, skipping dot entries when ignore_hidden
def _list_subdirectories(current_path, ignore_hidden):
    subdirs = []
    for entry in os.listdir(current_path):
        if ignore_hidden and entry.startswith("."):
            continue
        entry_path = join_paths(current_path, entry)
        if is_path_directory(entry_path):
            subdirs.append(entry_path)
    return subdirs

# Leaf directory info: its path, the count of files directly in it and their total size in bytes
def _summarize_leaf_directory(current_path, ignore_hidden):
    file_count = 0
    total_size = 0
    for entry in os.listdir(current_path):
        if ignore_hidden and entry.startswith("."):
            continue
        entry_path = join_paths(current_path, entry)
        if is_path_file(entry_path):
            file_count += 1
            total_size += get_file_size(entry_path)
    return {
        "path": current_path,
        "file_count": file_count,
        "total_size": total_size
    }

# Directories under root with no subdirectories, as dicts of path, file_count and total_size in bytes
def build_leaf_directory_list(
    root,
    excludes = None,
    ignore_hidden = True):

    # Get excludes
    excludes = [] if excludes is None else excludes

    # Build leaf dirs
    leaf_dirs = []
    root = os.path.normpath(root)
    work_queue = [root]
    while work_queue:
        current_path = work_queue.pop()

        # Skip invalid directories
        if not is_path_directory(current_path):
            continue

        # Get relative path for exclude checking
        rel_path = current_path[len(root):].lstrip(os.sep)

        # Skip excluded directories
        if rel_path and matches_exclude_pattern(rel_path, excludes):
            continue

        # If has subdirectories, add them to queue
        subdirs = _list_subdirectories(current_path, ignore_hidden)
        if subdirs:
            work_queue.extend(subdirs)
            continue

        # This is a leaf directory
        leaf_dirs.append(_summarize_leaf_directory(current_path, ignore_hidden))
    return leaf_dirs

# Returns the leaf directories as (small, large), where large ones exceed a threshold
def split_leaf_directory_list(
    root,
    excludes = None,
    ignore_hidden = True,
    large_file_count = None,
    large_total_size = None):
    excludes = [] if excludes is None else excludes
    small_dirs = []
    large_dirs = []
    for dir_info in build_leaf_directory_list(root, excludes, ignore_hidden):
        is_large = False
        if large_file_count is not None and dir_info["file_count"] > large_file_count:
            is_large = True
        if large_total_size is not None and dir_info["total_size"] > large_total_size:
            is_large = True
        if is_large:
            large_dirs.append(dir_info)
        else:
            small_dirs.append(dir_info)
    return small_dirs, large_dirs

# Group files by their parent directory
def group_files_by_directory(files):
    groups = {}
    for file_path in files:
        dir_path = get_filename_directory(file_path) or ""
        if dir_path not in groups:
            groups[dir_path] = []
        groups[dir_path].append(file_path)
    return groups

###########################################################
# Path conversion utilities
###########################################################

# Whether a top-level component is kept: always without a valid root or filter, else only as a file or dir under it
def _is_kept_top_level_path(path_front, path_root, only_files, only_dirs):
    if not is_path_valid(path_root) or not (only_files or only_dirs):
        return True
    path_full = os.path.join(path_root, path_front)
    if only_files and os.path.isfile(path_full):
        return True
    return bool(only_dirs and os.path.isdir(path_full))

# Sorted first components of each path, kept only when they are files or dirs under path_root if asked
def convert_to_top_level_paths(path_list, path_root = None, only_files = False, only_dirs = False):
    top_level_paths = set()
    for path in path_list:
        path_offset = get_filename_drive_offset(path)
        path_front = get_filename_front(path_offset)
        if _is_kept_top_level_path(path_front, path_root, only_files, only_dirs):
            top_level_paths.add(path_front)
    return strings.sort_strings(top_level_paths)

# Get relative path from a directory, or None when there is no route (another drive)
def get_relative_path(path, start_dir):
    try:
        return os.path.relpath(path, start_dir)
    except ValueError:
        return None

# Sorted paths with the base_dir prefix stripped, using OS separators
def convert_file_list_to_relative_paths(file_list, base_dir):
    replacement = normalize_file_path(base_dir, separator = config.OS_PATHSEP)
    if not replacement.endswith(config.OS_PATHSEP):
        replacement += config.OS_PATHSEP
    relative_file_list = []
    for filename in file_list:
        normalized_filename = normalize_file_path(filename, separator = config.OS_PATHSEP)
        relative_file_list.append(normalized_filename.removeprefix(replacement))
    return strings.sort_strings(relative_file_list)

# Sorted paths each joined onto base_dir
def convert_file_list_to_absolute_paths(file_list, base_dir):
    absolute_file_list = []
    for filename in file_list:
        absolute_file_list.append(os.path.join(base_dir, filename))
    return strings.sort_strings(absolute_file_list)

# Collapse a path in POSIX, Windows or native style, then turn backslashes into separator
def normalize_file_path(path, force_posix = False, force_windows = False, separator = os.sep):
    normalized_path = path
    if force_posix:
        normalized_path = posixpath.normpath(path)
    elif force_windows:
        normalized_path = ntpath.normpath(path)
    else:
        normalized_path = os.path.normpath(path)
    normalized_path = normalized_path.replace("\\", separator)
    return normalized_path

# Split on splitter and normalize each part, dropping the drive anchor from every part after the first
def split_file_path(path, splitter):
    split_paths = []
    for idx, part in enumerate(path.split(splitter)):
        norm_part = normalize_file_path(part)
        if idx == 0:
            split_paths.append(norm_part)
        else:
            split_paths.append(get_filename_drive_offset(norm_part))
    return split_paths

# Move a path from under old_base_path to under new_base_path; returned normalized but unchanged when outside it
def rebase_file_path(path, old_base_path, new_base_path):
    norm_path = normalize_file_path(path)
    norm_old_base_path = normalize_file_path(old_base_path)
    norm_new_base_path = normalize_file_path(new_base_path)
    old_prefix = norm_old_base_path.rstrip(os.sep) + os.sep
    if norm_path == norm_old_base_path:
        remainder = ""
    elif norm_path.startswith(old_prefix):
        remainder = norm_path[len(old_prefix):]
    else:
        return norm_path
    return normalize_file_path(os.path.join(norm_new_base_path, remainder))

# rebase_file_path applied to each path, keeping order
def rebase_file_paths(paths, old_base_path, new_base_path):
    rebased_paths = []
    for path in paths:
        rebased_paths.append(rebase_file_path(path, old_base_path, new_base_path))
    return rebased_paths

# Join strings and enum values into one normalized path; raises TypeError on any other type
def join_paths(*paths):
    processed_paths = []
    for path in paths:
        if isinstance(path, config.EnumType):
            processed_paths.append(path.val())
        elif isinstance(path, str):
            processed_paths.append(path)
        else:
            raise TypeError(f"Path {path} must be a string or an Enum, not {type(path)}.")
    return os.path.normpath(os.path.join(*processed_paths))

###########################################################
# Directory info utilities
###########################################################

# Last component of the path
def get_directory_name(path):
    return str(pathlib.Path(path).name)

# Path components as a list, anchor first
def get_directory_parts(path):
    return list(pathlib.Path(path).parts)

# Path with its last component removed
def get_directory_parent(path):
    return str(pathlib.Path(path).parent)

# First component of the path; empty for an empty path
def get_directory_front(path):
    for part in get_directory_parts(path):
        return part
    return ""

# Total bytes of the files under the directory, recursively
def get_directory_size(path):
    return sum(p.stat().st_size for p in pathlib.Path(path).rglob('*') if p.is_file())

# Sorted entry names in the directory, without excluded prefixes; empty when it is missing
def get_directory_contents(path, excludes = None):
    excludes = [] if excludes is None else excludes
    contents = []
    if does_path_exist(path):
        if os.path.isdir(path):
            contents = os.listdir(path)
    return prune_paths(contents, excludes)

# Root anchor such as / or C:\, read as POSIX when it starts with / and as Windows otherwise
def get_directory_anchor(path):
    if path.startswith(config.DRIVE_ROOT_POSIX):
        return str(pathlib.PurePosixPath(path).anchor)
    return str(pathlib.PureWindowsPath(path).anchor)

# Lowercased first character of the anchor, the drive letter on Windows; empty without one
def get_directory_drive(path):
    anchor = get_directory_anchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Path with its anchor removed
def get_directory_drive_offset(path):
    anchor = get_directory_anchor(path)
    if len(anchor) == 0:
        return path
    return path[len(anchor):]

# Check if directory is empty
def is_directory_empty(path):
    return len(get_directory_contents(path)) == 0

# Check if directory contains files
def does_directory_contain_files(path, recursive = True):
    if recursive:
        return len(build_file_list(path)) > 0
    files = []
    for obj in get_directory_contents(path):
        obj_path = os.path.join(path, obj)
        if os.path.isfile(obj_path):
            files.append(obj)
    return len(files) > 0

# Check if directory contains files by extensions
def does_directory_contain_files_by_extensions(path, extensions = None, recursive = True):
    extensions = [] if extensions is None else extensions
    if recursive:
        return len(build_file_list_by_extensions(path, extensions = extensions)) > 0
    files = []
    for obj in get_directory_contents(path):
        obj_path = os.path.join(path, obj)
        if os.path.isfile(obj_path):
            if does_filename_match_extensions(obj_path, extensions):
                files.append(obj)
    return len(files) > 0

# Check if directory contains symlink dirs
def does_directory_contain_symlink_dirs(path):
    return len(build_symlink_directory_list(path)) > 0

# Dict of the name, parts, parent, size, contents, drive details and emptiness of a directory
def get_directory_info(path):
    info = {}
    info["orig"] = path
    info["name"] = get_directory_name(path)
    info["parts"] = get_directory_parts(path)
    info["parent"] = get_directory_parent(path)
    info["front"] = get_directory_front(path)
    info["size"] = get_directory_size(path)
    info["contents"] = get_directory_contents(path)
    info["anchor"] = get_directory_anchor(path)
    info["drive"] = get_directory_drive(path)
    info["drive_offset"] = get_directory_drive_offset(path)
    info["is_empty"] = is_directory_empty(path)
    info["has_files"] = does_directory_contain_files(path)
    return info

###########################################################
# Filename info utilities
###########################################################

# Path components as a list, anchor first
def get_filename_parts(path):
    return list(pathlib.Path(path).parts)

# Parent directory of the file
def get_filename_directory(path):
    return str(pathlib.Path(path).parent)

# First component of the path; empty for an empty path
def get_filename_front(path):
    for part in get_filename_parts(path):
        return part
    return ""

# [path without extension, extension], with tarball suffixes such as .tar.gz kept whole
def get_filename_split(path):
    filename_ext = get_filename_extension(path)
    if not filename_ext:
        return [path, ""]
    filename_remainder = path[:-len(filename_ext)]
    return [filename_remainder, filename_ext]

# File name without directory or extension, with tarball suffixes such as .tar.gz removed whole
def get_filename_basename(path):
    filename = pathlib.Path(path).name
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if filename.endswith(tarball_ext):
            return filename[:-len(tarball_ext)]
    return str(pathlib.Path(path).stem)

# File suffix including the dot, with tarball suffixes such as .tar.gz returned whole; empty without one
def get_filename_extension(path):
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if path.endswith(tarball_ext):
            return tarball_ext
    return pathlib.Path(path).suffix

# Root anchor such as / or C:\, read as POSIX when it starts with / and as Windows otherwise
def get_filename_anchor(path):
    if path.startswith(config.DRIVE_ROOT_POSIX):
        return str(pathlib.PurePosixPath(path).anchor)
    return str(pathlib.PureWindowsPath(path).anchor)

# Lowercased first character of the anchor, the drive letter on Windows; empty without one
def get_filename_drive(path):
    anchor = get_filename_anchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Path with its anchor removed
def get_filename_drive_offset(path):
    anchor = get_filename_anchor(path)
    if len(anchor) == 0:
        return path
    return path[len(anchor):]

# Path with its first component removed
def get_filename_front_slice(path):
    return rebase_file_path(path, get_filename_front(path) + config.OS_PATHSEP, "")

# Check if filename matches extensions
def does_filename_match_extensions(path, extensions = None):
    extensions = [] if extensions is None else extensions
    if not isinstance(extensions, list):
        return False
    lowered = path.lower()
    for extension in extensions:
        if lowered.endswith(extension.lower()):
            return True
    return False

# File name with extension but no directory
def get_filename_file(path):
    return get_filename_basename(path) + get_filename_extension(path)

# Same path with its extension swapped for new_extension, which includes the dot
def change_filename_extension(path, new_extension):
    return join_paths(get_filename_directory(path), get_filename_basename(path) + new_extension)

# Size of the file in bytes; raises OSError when it is missing
def get_file_size(path):
    return os.path.getsize(path)

# MIME type libmagic detects; empty when python-magic is missing or the file cannot be read
def get_file_mime_type(path):
    try:
        magic = _get_magic()
    except ImportError:
        return ""
    try:
        return magic.from_file(path, mime=True)
    except (OSError, magic.MagicException):
        return ""

# Hours since the file was last modified; infinity when it cannot be read
def get_file_age_in_hours(path):
    try:
        file_mtime = os.path.getmtime(path)
        current_time = time.time()
        age_seconds = current_time - file_mtime
        return age_seconds / 3600.0  # Convert to hours
    except OSError:
        return float('inf')  # Return infinite age if file doesn't exist or error

# Get file modification time as timestamp
def get_file_mod_time(path):
    try:
        return int(os.path.getmtime(path))
    except OSError:
        return 0

# Dict of the parts, directory, base name, extension, drive details, size and MIME type of a file
def get_filename_info(path):
    info = {}
    info["orig"] = path
    info["parts"] = get_filename_parts(path)
    info["dir"] = get_filename_directory(path)
    info["front"] = get_filename_front(path)
    info["file_split"] = get_filename_split(path)
    info["file_base"] = get_filename_basename(path)
    info["file_ext"] = get_filename_extension(path)
    info["file_anchor"] = get_filename_anchor(path)
    info["file_drive"] = get_filename_drive(path)
    info["file_drive_offset"] = get_filename_drive_offset(path)
    info["file"] = get_filename_file(path)
    info["size"] = get_file_size(path)
    info["mime"] = get_file_mime_type(path)
    return info

###########################################################
# Path validation and filtering
###########################################################

# Drive to validate against and the path without it: its own drive, else the system drive, else none; no drive off Windows
def _split_validation_drive(path):
    if os.name != "nt":
        return "", path
    drive, path = os.path.splitdrive(path)
    if not os.path.isdir(drive):
        drive = os.environ.get("SystemDrive", "C:")
    if not os.path.isdir(drive):
        drive = ""
    return drive, path

# Whether lstat rejects the name itself as invalid or too long, rather than just not finding it
def _is_rejected_path_name(location):
    try:
        os.lstat(location)
    except OSError as e:
        if getattr(e, "winerror", None) == 123:
            return True
        if e.errno in {errno.ENAMETOOLONG, errno.ERANGE}:
            return True
    return False

# Check if path is valid
# https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
# https://gist.github.com/mo-han/240b3ef008d96215e352203b88be40db
def is_path_valid(path):
    try:
        if not isinstance(path, str) or not path or len(path) == 0:
            return False
        drive, path = _split_validation_drive(path)
        parts = pathlib.Path(path).parts
        if not parts:
            check_list = [path]
        else:
            check_list = [os.path.join(*parts), *parts]
        for x in check_list:
            if _is_rejected_path_name(drive + x):
                return False
    except (TypeError, ValueError):
        return False
    return True

# Check if a path should be excluded (any exclude token appears in a path component)
def is_exclude_path(path, excludes = ()):
    for exclude in excludes:
        if any(exclude in part for part in path.split(os.sep)):
            return True
    return False

###########################################################
# Runnable commands
###########################################################

# Executable path for cmd, trying each search dir with Windows program extensions before PATH; None when not found
def get_runnable_command_path(cmd, search_dirs = ()):
    for search_dir in search_dirs:
        potential_paths = [join_paths(search_dir, cmd)]
        for cmd_ext in config.WindowsProgramFileType.cvalues():
            potential_paths.append(join_paths(search_dir, cmd + cmd_ext))
        for potential_path in potential_paths:
            verified_path = shutil.which(potential_path)
            if verified_path:
                return verified_path
    return shutil.which(cmd)

# Check if runnable command
def is_runnable_command(cmd, search_dirs = None):
    search_dirs = [] if search_dirs is None else search_dirs
    cmd_path = get_runnable_command_path(cmd, search_dirs)
    if not cmd_path:
        return False
    return True
