# Imports
import os
import os.path
import sys
import zipfile
import re

# Local imports
import config
import command
import programs
import system
import logger
import paths
import environment
import fileops
import sandbox

# Determine if file is a known archive
def is_known_archive(archive_file, extensions = [], mime_types = []):
    for ext in extensions:
        if archive_file.lower().endswith(ext.lower()):
            return True
    if not paths.is_path_file(archive_file):
        return False
    actual_mime_type = paths.get_file_mime_type(archive_file)
    for potential_mime_type in mime_types:
        if potential_mime_type.lower() in actual_mime_type.lower():
            return True
    return False

# Determine if file is an archive
def is_archive(archive_file):
    if is_zip_archive(archive_file):
        return True
    elif is_7z_archive(archive_file):
        return True
    elif is_tarball_archive(archive_file):
        return True
    elif is_disc_archive(archive_file):
        return True
    elif is_exe_archive(archive_file):
        return True
    elif is_appimage_archive(archive_file):
        return True
    return False

# Determine if file is a zip archive
def is_zip_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveZipFileType.cvalues(),
        mime_types = config.mime_types_zip)

# Determine if file is a 7z archive
def is_7z_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.Archive7zFileType.cvalues(),
        mime_types = config.mime_types_7z)

# Determine if file is a rar archive
def is_rar_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveRarFileType.cvalues(),
        mime_types = config.mime_types_rar)

# Determine if file is a tarball archive
def is_tarball_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveTarballFileType.cvalues(),
        mime_types = config.mime_types_tarball)

# Determine if file is a disc archive
def is_disc_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = config.ArchiveDiscFileType.cvalues(),
        mime_types = config.mime_types_disc)

# Determine if file is an exe archive
def is_exe_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = [config.WindowsProgramFileType.EXE.cval()],
        mime_types = config.mime_types_exe)

# Determine if file is an appimage archive
def is_appimage_archive(archive_file):
    return is_known_archive(
        archive_file = archive_file,
        extensions = [config.LinuxProgramFileType.APPIMAGE.cval()],
        mime_types = config.mime_types_appimage)

# Get archive type
def get_archive_type(archive_file):
    archive_ext = paths.get_filename_extension(archive_file)
    for archive_type in config.ArchiveFileType.members():
        if archive_ext == archive_type.cval():
            return archive_type
    return None

# Determine if creatable archive type
def is_creatable_archive_type(archive_type):
    if archive_type in config.ArchiveZipFileType.members():
        return True
    if archive_type in config.Archive7zFileType.members():
        return True
    return False

# Determine if extractable archive type
def is_extractable_archive_type(archive_type):
    if archive_type in config.ArchiveZipFileType.members():
        return True
    if archive_type in config.Archive7zFileType.members():
        return True
    if archive_type in config.ArchiveTarballFileType.members():
        return True
    if archive_type in config.ArchiveDiscFileType.members():
        return True
    return False

# Check archive checksums
def get_archive_checksums(archive_file):
    checksums = []
    if paths.is_path_file(archive_file):
        if is_zip_archive(archive_file):
            with zipfile.ZipFile(archive_file) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    entry = {}
                    entry["path"] = info.filename
                    entry["crc"] = hex(info.CRC)
                    checksums.append(entry)
    return checksums

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
    archive_type,
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
    archive_type = get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if creatable
    if not is_creatable_archive_type(archive_type):
        logger.log_error("Unable to create archives of type %s" % archive_type.val())
        return False

    # Get path to add
    path_to_add = sandbox.translate_path_if_necessary(
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
        options = command.create_command_options(
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
        archive_type = archive_type,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create archive from folder
def create_archive_from_folder(
    archive_file,
    source_dir,
    excludes = [],
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
    archive_type = get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if creatable
    if not is_creatable_archive_type(archive_type):
        logger.log_error("Unable to create archives of type %s" % archive_type.val())
        return False

    # Create list of objects to add
    objs_to_add = []
    for obj in paths.get_directory_contents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandbox.translate_path_if_necessary(
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
        options = command.create_command_options(
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
        archive_type = archive_type,
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
    if is_tarball_archive(archive_file):
        if programs.is_tool_installed("Tar"):
            archive_tool = programs.get_tool_program("Tar")
        if not archive_tool:
            logger.log_error("Tar was not found")
            return False
    else:
        if programs.is_tool_installed("7-Zip"):
            archive_tool = programs.get_tool_program("7-Zip")
        if not archive_tool:
            logger.log_error("7-Zip was not found")
            return False

    # Get archive type
    archive_type = get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if extractable
    if not is_extractable_archive_type(archive_type):
        logger.log_error("Unable to extract archives of type %s" % archive_type.val())
        return False

    # Get extract command
    extract_cmd = []
    if is_tarball_archive(archive_file):
        extract_cmd = [
            archive_tool,
            "xvf",
            archive_file,
            "-C", extract_dir
        ]
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
        options = command.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
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
        options = command.create_command_options(
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)

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
        options = command.create_command_options(
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
            size = match.group(2)
            compressed = match.group(3)
            path = match.group(4)
            if not attr.startswith("D.."):
                all_paths.append(path)

    # Condense paths
    condensed_paths = []
    for path in sorted(all_paths, key=lambda x: -len(x)):
        if not any(path + "/" == existing[:len(path) + 1] for existing in condensed_paths):
            condensed_paths.append(path)
    return condensed_paths
