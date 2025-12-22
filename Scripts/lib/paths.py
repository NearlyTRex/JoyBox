# Imports
import os
import errno
import pathlib

# Local imports
import config
import text

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
