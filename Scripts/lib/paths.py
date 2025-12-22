# Imports
import os
import errno
import pathlib
import posixpath
import ntpath
import time

# Local imports
import config
import text
import strings

###########################################################
# Path checking and validation utilities
###########################################################

# Check if path is valid
# https://stackoverflow.com/questions/9532499/check-whether-a-path-is-valid-in-python-without-creating-a-file-at-the-paths-ta
# https://gist.github.com/mo-han/240b3ef008d96215e352203b88be40db
def is_path_valid(path):
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
    if not does_path_exist(path):
        return False
    return os.path.islink(path)

# Check if path is file or directory
def is_path_file_or_directory(path):
    if not is_path_valid(path):
        return False
    if not does_path_exist(path):
        return False
    return os.path.isfile(path) or os.path.isdir(path) and not os.path.islink(path)

# Check if drive letter is valid
def is_drive_letter_valid(drive_letter):
    if not drive_letter or not isinstance(drive_letter, str) or len(drive_letter) == 0:
        return False
    return drive_letter.isalpha()

# Replace invalid path characters
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

# Prune paths
def prune_paths(paths, excludes = []):
    new_paths = set()
    for path in paths:
        should_add = True
        for exclude in excludes:
            if path.startswith(exclude):
                should_add = False
        if should_add:
            new_paths.add(path)
    return strings.sort_strings(new_paths)

# Prune child paths
def prune_child_paths(paths):
    filtered_paths = list(paths)
    if config.token_game_install_dir in filtered_paths:
        has_specific_install_paths = any(
            path.startswith(config.token_game_install_dir + "/")
            for path in filtered_paths
        )
        if has_specific_install_paths:
            filtered_paths = [p for p in filtered_paths if p != config.token_game_install_dir]
    new_paths = set()
    for path in strings.sort_strings(filtered_paths):
        if not any(is_parent_path(added_path, path) for added_path in new_paths):
            new_paths.add(path)
    return strings.sort_strings(new_paths)

# Build file list
def build_file_list(root, excludes = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    files = []
    if not is_path_valid(root):
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
    return prune_paths(files, excludes)

# Build file list by extensions
def build_file_list_by_extensions(root, excludes = [], extensions = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    files = []
    for file in build_file_list(root, excludes, new_relative_path, use_relative_paths, ignore_symlinks, follow_symlink_dirs):
        base, ext = get_filename_split(file)
        if isinstance(extensions, list) and len(extensions) > 0:
            if ext in extensions or ext.lower() in extensions or ext.upper() in extensions:
                files.append(file)
        else:
            files.append(file)
    return strings.sort_strings(files)

# Build directory list
def build_directory_list(root, excludes = [], new_relative_path = "", use_relative_paths = False, ignore_symlinks = False, follow_symlink_dirs = False):
    directories = []
    if not is_path_valid(root):
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
    return prune_paths(directories, excludes)

# Build empty directory list
def build_empty_directory_list(root, excludes = [], new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in build_directory_list(root, excludes, new_relative_path, use_relative_paths):
        if is_directory_empty(potential_dir):
            directories.append(potential_dir)
    return directories

# Build symlink directory list
def build_symlink_directory_list(root, excludes = [], new_relative_path = "", use_relative_paths = False):
    directories = []
    for potential_dir in build_directory_list(root, excludes, new_relative_path, use_relative_paths):
        if os.path.islink(potential_dir):
            directories.append(potential_dir)
    return directories

###########################################################
# Path conversion utilities
###########################################################

# Convert to top level paths
def convert_to_top_level_paths(path_list, path_root = None, only_files = False, only_dirs = False):
    top_level_paths = set()
    for path in path_list:
        path_offset = get_filename_drive_offset(path)
        path_front = get_filename_front(path_offset)
        should_save_path = False
        if is_path_valid(path_root):
            path_full = os.path.join(path_root, path_front)
            if only_files and os.path.isfile(path_full):
                should_save_path = True
            elif only_dirs and os.path.isdir(path_full):
                should_save_path = True
        else:
            should_save_path = True
        if should_save_path:
            top_level_paths.add(path_front)
    return strings.sort_strings(top_level_paths)

# Convert file list to relative paths
def convert_file_list_to_relative_paths(file_list, base_dir):
    replacement = normalize_file_path(base_dir, separator = config.os_pathsep)
    if not replacement.endswith(config.os_pathsep):
        replacement += config.os_pathsep
    relative_file_list = []
    for filename in file_list:
        normalized_filename = normalize_file_path(filename, separator = config.os_pathsep)
        normalized_filename = normalized_filename.replace(replacement, "")
        relative_file_list.append(normalized_filename)
    return strings.sort_strings(relative_file_list)

# Convert file list to absolute paths
def convert_file_list_to_absolute_paths(file_list, base_dir):
    absolute_file_list = []
    for filename in file_list:
        absolute_file_list.append(os.path.join(base_dir, filename))
    return strings.sort_strings(absolute_file_list)

# Normalize file path
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

# Split file path
def split_file_path(path, splitter):
    split_paths = []
    for idx, part in enumerate(path.split(splitter)):
        norm_part = normalize_file_path(part)
        if idx == 0:
            split_paths.append(norm_part)
        else:
            split_paths.append(get_filename_drive_offset(norm_part))
    return split_paths

# Rebase file path
def rebase_file_path(path, old_base_path, new_base_path):
    norm_path = normalize_file_path(path)
    norm_old_base_path = normalize_file_path(old_base_path)
    norm_new_base_path = normalize_file_path(new_base_path)
    rebased_path = normalize_file_path(norm_path.replace(norm_old_base_path, norm_new_base_path))
    return rebased_path

# Rebase file paths
def rebase_file_paths(paths, old_base_path, new_base_path):
    rebased_paths = []
    for path in paths:
        rebased_paths.append(rebase_file_path(path, old_base_path, new_base_path))
    return rebased_paths

# Join paths
def join_paths(*paths):
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
# Directory info utilities
###########################################################

# Get directory name
def get_directory_name(path):
    return str(pathlib.Path(path).name)

# Get directory parts
def get_directory_parts(path):
    return list(pathlib.Path(path).parts)

# Get directory parent
def get_directory_parent(path):
    return str(pathlib.Path(path).parent)

# Get directory front
def get_directory_front(path):
    for part in get_directory_parts(path):
        return part
    return ""

# Get directory size
def get_directory_size(path):
    return sum(p.stat().st_size for p in pathlib.Path(path).rglob('*'))

# Get directory contents
def get_directory_contents(path, excludes = []):
    contents = []
    if does_path_exist(path):
        if os.path.isdir(path):
            contents = os.listdir(path)
    return prune_paths(contents, excludes)

# Get directory anchor
def get_directory_anchor(path):
    if path.startswith(config.drive_root_posix):
        return str(pathlib.PurePosixPath(path).anchor)
    else:
        return str(pathlib.PureWindowsPath(path).anchor)

# Get directory drive
def get_directory_drive(path):
    anchor = get_directory_anchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Get directory drive offset
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
    else:
        files = []
        for obj in get_directory_contents(path):
            obj_path = os.path.join(path, obj)
            if os.path.isfile(obj_path):
                files.append(obj)
        return len(files)

# Check if directory contains files by extensions
def does_directory_contain_files_by_extensions(path, extensions = [], recursive = True):
    if recursive:
        return len(build_file_list_by_extensions(path, extensions = extensions)) > 0
    else:
        files = []
        for obj in get_directory_contents(path):
            obj_path = os.path.join(path, obj)
            if os.path.isfile(obj_path):
                for file_type in extensions:
                    if obj_path.endswith(file_type):
                        files.append(obj)
        return len(files)

# Check if directory contains symlink dirs
def does_directory_contain_symlink_dirs(path):
    return len(build_symlink_directory_list(path)) > 0

# Get directory info
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

# Get filename parts
def get_filename_parts(path):
    return list(pathlib.Path(path).parts)

# Get filename directory
def get_filename_directory(path):
    return str(pathlib.Path(path).parent)

# Get filename front
def get_filename_front(path):
    for part in get_filename_parts(path):
        return part
    return ""

# Get filename split
def get_filename_split(path):
    filename_ext = get_filename_extension(path)
    filename_remainder = path[:-(len(filename_ext))]
    return [filename_remainder, filename_ext]

# Get filename basename
def get_filename_basename(path):
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if path.endswith(tarball_ext):
            return path[:-len(tarball_ext)]
    return str(pathlib.Path(path).stem)

# Get filename extension
def get_filename_extension(path):
    for tarball_ext in config.ArchiveTarballFileType.cvalues():
        if path.endswith(tarball_ext):
            return tarball_ext
    return pathlib.Path(path).suffix

# Get filename anchor
def get_filename_anchor(path):
    if path.startswith(config.drive_root_posix):
        return str(pathlib.PurePosixPath(path).anchor)
    else:
        return str(pathlib.PureWindowsPath(path).anchor)

# Get filename drive
def get_filename_drive(path):
    anchor = get_filename_anchor(path)
    if len(anchor) == 0:
        return ""
    return anchor[0].lower()

# Get filename drive offset
def get_filename_drive_offset(path):
    anchor = get_filename_anchor(path)
    if len(anchor) == 0:
        return path
    return path[len(anchor):]

# Get filename front slice
def get_filename_front_slice(path):
    return rebase_file_path(path, get_filename_front(path) + config.os_pathsep, "")

# Get filename file
def get_filename_file(path):
    return get_filename_basename(path) + get_filename_extension(path)

# Change filename extension
def change_filename_extension(path, new_extension):
    directory = get_filename_directory(path)
    basename = get_filename_basename(path)
    if directory:
        return join_paths(directory, basename + new_extension)
    return basename + new_extension

# Get file size
def get_file_size(path):
    return os.path.getsize(path)

# Get file mime type
def get_file_mime_type(path):
    try:
        import magic
        return magic.from_file(path, mime=True)
    except:
        pass
    return ""

# Get file age in hours
def get_file_age_in_hours(path):
    try:
        file_mtime = os.path.getmtime(path)
        current_time = time.time()
        age_seconds = current_time - file_mtime
        return age_seconds / 3600.0  # Convert to hours
    except:
        return float('inf')  # Return infinite age if file doesn't exist or error

# Get file modification time as timestamp
def get_file_mod_time(path):
    try:
        return os.path.getmtime(path)
    except:
        return None

# Get filename info
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
