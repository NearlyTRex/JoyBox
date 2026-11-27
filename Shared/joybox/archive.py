# Imports
import os
import os.path
import re

# Local imports
from joybox import archiveinfo
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import programs
from joybox import logger
from joybox import paths
from joybox import fileops
from joybox import sandboxpaths

# Get archive compression flags
def get_archive_compression_flags(archive_type, password, volume_size):
    compression_flags = []
    if archive_type == config.ArchiveFileType.ZIP:
        compression_flags += [
            "-tzip", # Archive format
            "-bb3", # Show files being added
            "-mm=Deflate", # Compression method
            "-mx=7", # Compression level
            "-mtc=off", # Do no store NTFS timestamps for files
            "-mcu=on", # Use UTF-8 for file names that contain non-ASCII symbols
            "-mmt=on", # Use multithreading
            "-ma=1", # Reproducible archive
        ]
    elif archive_type == config.ArchiveFileType.SEVENZIP:
        compression_flags += [
            "-t7z", # Archive format
            "-bb3", # Show files being added
            "-mtc=off", # Do no store NTFS timestamps for files
            "-mmt=on", # Use multithreading
            "-ma=1", # Reproducible archive
        ]
    if isinstance(password, str) and len(password) > 0:
        compression_flags += [
            "-p%s" % password
        ]
    if isinstance(volume_size, str) and len(volume_size) > 0:
        compression_flags += [
            "-v%s" % volume_size
        ]
    return compression_flags

# Check archive compression output files
def check_archive_compression_output_files(
    archive_file,
    volume_size,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get output files
    output_files = []
    if isinstance(volume_size, str) and len(volume_size) > 0:

        # Search for potential volume files
        for i in range(1, 999):
            potential_file = archive_file + "." + str(i).zfill(3)
            if not os.path.exists(potential_file):
                break
            output_files.append(potential_file)

        # Rename for single files
        if len(output_files) == 1:
            old_output_file = output_files[0]
            new_output_file = old_output_file.replace(".001", "")
            fileops.move_file_or_directory(
                src = old_output_file,
                dest = new_output_file,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            output_files = [new_output_file]
    else:
        output_files.append(archive_file)

    # Check output files
    if len(output_files) == 0:
        return False
    for output_file in output_files:
        if not os.path.exists(output_file):
            return False
    return True

# Create archive from file
def create_archive_from_file(
    archive_file,
    source_file,
    password = None,
    volume_size = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if programs.is_tool_installed("7-Zip"):
        archive_tool = programs.get_tool_program("7-Zip")
    if not archive_tool:
        logger.log_error("7-Zip was not found")
        return False

    # Get archive type
    archive_type = archiveinfo.get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if creatable
    if not archiveinfo.is_creatable_archive_type(archive_type):
        logger.log_error("Unable to create archives of type %s" % archive_type.val())
        return False

    # Get path to add
    path_to_add = sandboxpaths.translate_path_if_necessary(
        path = source_file,
        program_exe = archive_tool,
        program_name = "7-Zip")

    # Get create command
    create_command = [
        archive_tool,
        "a"
    ]
    create_command += get_archive_compression_flags(
        archive_type = archive_type,
        password = password,
        volume_size = volume_size)
    create_command += [
        archive_file,
        path_to_add
    ]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = commandbase.create_command_options(
            cwd = paths.get_filename_directory(source_file),
            output_paths = [archive_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check output files
    return check_archive_compression_output_files(
        archive_file = archive_file,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create archive from folder
def create_archive_from_folder(
    archive_file,
    source_dir,
    excludes = (),
    password = None,
    volume_size = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if programs.is_tool_installed("7-Zip"):
        archive_tool = programs.get_tool_program("7-Zip")
    if not archive_tool:
        logger.log_error("7-Zip was not found")
        return False

    # Get archive type
    archive_type = archiveinfo.get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if creatable
    if not archiveinfo.is_creatable_archive_type(archive_type):
        logger.log_error("Unable to create archives of type %s" % archive_type.val())
        return False

    # Create list of objects to add
    objs_to_add = []
    for obj in paths.get_directory_contents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandboxpaths.translate_path_if_necessary(
            path = paths.join_paths(source_dir, obj),
            program_exe = archive_tool,
            program_name = "7-Zip")
        objs_to_add.append(path_to_add)

    # Get create command
    create_command = [
        archive_tool,
        "a"
    ]
    create_command += get_archive_compression_flags(
        archive_type = archive_type,
        password = password,
        volume_size = volume_size)
    create_command += [
        archive_file
    ]
    create_command += objs_to_add

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = commandbase.create_command_options(
            cwd = source_dir,
            output_paths = [archive_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_directory(
            src = source_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check output files
    return check_archive_compression_output_files(
        archive_file = archive_file,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract archive
def extract_archive(
    archive_file,
    extract_dir,
    password = None,
    skip_existing = False,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if archiveinfo.is_tarball_archive(archive_file):
        if programs.is_tool_installed("Tar"):
            archive_tool = programs.get_tool_program("Tar")
        if not archive_tool:
            logger.log_error("Tar was not found")
            return False
    elif archiveinfo.is_rar_archive(archive_file):
        if programs.is_tool_installed("Unrar"):
            archive_tool = programs.get_tool_program("Unrar")
        if not archive_tool:
            logger.log_error("Unrar was not found")
            return False
    elif archiveinfo.is_stuffit_archive(archive_file):
        if programs.is_tool_installed("Unar"):
            archive_tool = programs.get_tool_program("Unar")
        if not archive_tool:
            logger.log_error("Unar was not found")
            return False
    else:
        if programs.is_tool_installed("7-Zip"):
            archive_tool = programs.get_tool_program("7-Zip")
        if not archive_tool:
            logger.log_error("7-Zip was not found")
            return False

    # Get archive type
    archive_type = archiveinfo.get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if extractable
    if not archiveinfo.is_extractable_archive_type(archive_type):
        logger.log_error("Unable to extract archives of type %s" % archive_type.val())
        return False

    # Create destination directory
    fileops.make_directory(
        src = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get extract command
    extract_cmd = []
    if archiveinfo.is_tarball_archive(archive_file):
        extract_cmd = [
            archive_tool,
            "xvf",
            archive_file,
            "-C", extract_dir
        ]
    elif archiveinfo.is_rar_archive(archive_file):
        extract_cmd = [
            archive_tool,
            "x",
            "-y"
        ]
        if isinstance(password, str) and len(password) > 0:
            extract_cmd += ["-p%s" % password]
        else:
            extract_cmd += ["-p-"]
        if skip_existing:
            extract_cmd += ["-o-"]
        else:
            extract_cmd += ["-o+"]
        extract_cmd += [
            archive_file,
            extract_dir + os.sep
        ]
    elif archiveinfo.is_stuffit_archive(archive_file):
        extract_cmd = [
            archive_tool,
            "-o", extract_dir,
            "-D"
        ]
        if isinstance(password, str) and len(password) > 0:
            extract_cmd += ["-p", password]
        if skip_existing:
            extract_cmd += ["-s"]
        else:
            extract_cmd += ["-f"]
        extract_cmd += [archive_file]
    else:
        extract_cmd = [
            archive_tool,
            "x",
            archive_file,
            "-o" + extract_dir,
            "-bb3"
        ]
        if isinstance(password, str) and len(password) > 0:
            extract_cmd += [
                "-p%s" % password
            ]
        if skip_existing:
            extract_cmd += ["-aos"]
        else:
            extract_cmd += ["-aoa"]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = commandbase.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Decode Shift-JIS names, which lzh archives store without saying so
    if archiveinfo.is_lzh_archive(archive_file):
        success = fileops.decode_legacy_filenames(
            src = extract_dir,
            encoding = "cp932",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir) and not paths.is_directory_empty(extract_dir)

# Test archive
def test_archive(
    archive_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if programs.is_tool_installed("7-Zip"):
        archive_tool = programs.get_tool_program("7-Zip")
    if not archive_tool:
        logger.log_error("7-Zip was not found")
        return False

    # Get test command
    test_cmd = [
        archive_tool,
        "t",
        archive_file
    ]

    # Run test command
    code = command.run_returncode_command(
        cmd = test_cmd,
        options = commandbase.create_command_options(
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# List archive
def list_archive(
    archive_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if programs.is_tool_installed("7-Zip"):
        archive_tool = programs.get_tool_program("7-Zip")
    if not archive_tool:
        logger.log_error("7-Zip was not found")
        return []

    # Get list command
    list_command = [
        archive_tool,
        "l", archive_file
    ]

    # Run list command
    list_output = command.run_output_command(
        cmd = list_command,
        options = commandbase.create_command_options(
            blocking_processes=[archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get output text
    list_text = list_output
    if isinstance(list_output, bytes):
        list_text = list_output.decode()

    # Get full list of paths
    all_paths = []
    for line in list_text.splitlines():
        pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (\S+)\s+(\d+)\s+(\d+)\s+(.+)$"
        match = re.match(pattern, line)
        if match:
            attr = match.group(1)
            path = match.group(4)
            if not attr.startswith("D.."):
                all_paths.append(path)

    # Condense paths
    condensed_paths = []
    for path in sorted(all_paths, key=lambda x: -len(x)):
        if not any(path + "/" == existing[:len(path) + 1] for existing in condensed_paths):
            condensed_paths.append(path)
    return condensed_paths
