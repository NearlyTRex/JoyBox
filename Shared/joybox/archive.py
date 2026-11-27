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

# 7-Zip flags for a zip or 7z archive, plus password and volume-split flags when given
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

# Whether 7-Zip wrote its output; a lone .001 volume is renamed to the plain archive name
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

# The installed tool's program, or None after logging that it was not found
def _find_archive_tool(tool_name):
    archive_tool = None
    if programs.is_tool_installed(tool_name):
        archive_tool = programs.get_tool_program(tool_name)
    if not archive_tool:
        logger.log_error("%s was not found" % tool_name)
        return None
    return archive_tool

# The archive's type when 7-Zip can create it, or None after logging why not
def _get_creatable_archive_type(archive_file):

    # Get archive type
    archive_type = archiveinfo.get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return None

    # Check if creatable
    if not archiveinfo.is_creatable_archive_type(archive_type):
        logger.log_error("Unable to create archives of type %s" % archive_type.val())
        return None
    return archive_type

# 7-Zip and the archive's creatable type, or (None, None) after logging why not
def _get_create_tool_and_type(archive_file):
    archive_tool = _find_archive_tool("7-Zip")
    if not archive_tool:
        return None, None
    archive_type = _get_creatable_archive_type(archive_file)
    if not archive_type:
        return None, None
    return archive_tool, archive_type

# Run 7-Zip's add command for the given paths from cwd; True when it exits 0
def _run_create_command(
    archive_tool,
    archive_type,
    archive_file,
    paths_to_add,
    cwd,
    password,
    volume_size,
    verbose,
    pretend_run,
    exit_on_failure):

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
    create_command += paths_to_add

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = commandbase.create_command_options(
            cwd = cwd,
            output_paths = [archive_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Remove the archived file or directory; nothing when original is None
def _remove_original(original, original_is_directory, verbose, pretend_run, exit_on_failure):
    if original and original_is_directory:
        fileops.remove_directory(
            src = original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif original:
        fileops.remove_file(
            src = original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Run the add command, remove the original file or directory when given, then check the output
def _create_archive(
    archive_tool,
    archive_type,
    archive_file,
    paths_to_add,
    cwd,
    password,
    volume_size,
    original,
    original_is_directory,
    verbose,
    pretend_run,
    exit_on_failure):

    # Run create command
    created = _run_create_command(
        archive_tool = archive_tool,
        archive_type = archive_type,
        archive_file = archive_file,
        paths_to_add = paths_to_add,
        cwd = cwd,
        password = password,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not created:
        return False

    # Clean up
    _remove_original(original, original_is_directory, verbose, pretend_run, exit_on_failure)

    # Check output files
    return check_archive_compression_output_files(
        archive_file = archive_file,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Compress one file into an archive with 7-Zip, optionally deleting the source; False on any failure
def create_archive_from_file(
    archive_file,
    source_file,
    password = None,
    volume_size = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool and archive type
    archive_tool, archive_type = _get_create_tool_and_type(archive_file)
    if not archive_tool:
        return False

    # Get path to add
    path_to_add = sandboxpaths.translate_path_if_necessary(
        path = source_file,
        program_exe = archive_tool,
        program_name = "7-Zip")

    # Create archive
    return _create_archive(
        archive_tool = archive_tool,
        archive_type = archive_type,
        archive_file = archive_file,
        paths_to_add = [path_to_add],
        cwd = paths.get_filename_directory(source_file),
        password = password,
        volume_size = volume_size,
        original = source_file if delete_original else None,
        original_is_directory = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The folder's top-level entries minus excludes, as paths 7-Zip can read
def _get_folder_paths_to_add(archive_tool, source_dir, excludes):
    objs_to_add = []
    for obj in paths.get_directory_contents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandboxpaths.translate_path_if_necessary(
            path = paths.join_paths(source_dir, obj),
            program_exe = archive_tool,
            program_name = "7-Zip")
        objs_to_add.append(path_to_add)
    return objs_to_add

# Compress a folder's contents, minus excludes, into an archive with 7-Zip; False on any failure
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

    # Get tool and archive type
    archive_tool, archive_type = _get_create_tool_and_type(archive_file)
    if not archive_tool:
        return False

    # Create list of objects to add
    objs_to_add = _get_folder_paths_to_add(archive_tool, source_dir, excludes)

    # Create archive
    return _create_archive(
        archive_tool = archive_tool,
        archive_type = archive_type,
        archive_file = archive_file,
        paths_to_add = objs_to_add,
        cwd = source_dir,
        password = password,
        volume_size = volume_size,
        original = source_dir if delete_original else None,
        original_is_directory = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# The tool that unpacks this archive: tar, unrar, unar, or 7-Zip for the rest
def _get_extract_tool_name(archive_file):
    if archiveinfo.is_tarball_archive(archive_file):
        return "Tar"
    if archiveinfo.is_rar_archive(archive_file):
        return "Unrar"
    if archiveinfo.is_stuffit_archive(archive_file):
        return "Unar"
    return "7-Zip"

# Whether the archive's type is known and extractable, logging why not
def _is_extractable_archive(archive_file):

    # Get archive type
    archive_type = archiveinfo.get_archive_type(archive_file)
    if not archive_type:
        logger.log_error("Unrecognized archive type for %s" % archive_file)
        return False

    # Check if extractable
    if not archiveinfo.is_extractable_archive_type(archive_type):
        logger.log_error("Unable to extract archives of type %s" % archive_type.val())
        return False
    return True

# Unrar's extract command; "-p-" stops it prompting when no password is given
def _build_rar_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing):
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
    return extract_cmd

# Unar's extract command, skipping or overwriting existing files
def _build_stuffit_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing):
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
    return extract_cmd

# 7-Zip's extract command, skipping or overwriting existing files
def _build_sevenzip_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing):
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
    return extract_cmd

# The extract command for the archive's tool
def _build_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing):
    if archiveinfo.is_tarball_archive(archive_file):
        return [
            archive_tool,
            "xvf",
            archive_file,
            "-C", extract_dir
        ]
    if archiveinfo.is_rar_archive(archive_file):
        return _build_rar_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing)
    if archiveinfo.is_stuffit_archive(archive_file):
        return _build_stuffit_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing)
    return _build_sevenzip_extract_command(archive_tool, archive_file, extract_dir, password, skip_existing)

# Decode Shift-JIS names, which lzh archives store without saying so; True for other archives
def _decode_lzh_names(archive_file, extract_dir, verbose, pretend_run, exit_on_failure):
    if archiveinfo.is_lzh_archive(archive_file):
        success = fileops.decode_legacy_filenames(
            src = extract_dir,
            encoding = "cp932",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# The tool that extracts this archive, or None after logging why it cannot be extracted
def _get_extract_tool(archive_file):
    archive_tool = _find_archive_tool(_get_extract_tool_name(archive_file))
    if not archive_tool:
        return None
    if not _is_extractable_archive(archive_file):
        return None
    return archive_tool

# Make the directory, run the extract command into it and fix lzh names; False on failure
def _extract_into_directory(
    archive_tool,
    archive_file,
    extract_dir,
    password,
    skip_existing,
    verbose,
    pretend_run,
    exit_on_failure):

    # Create destination directory
    fileops.make_directory(
        src = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Get extract command
    extract_cmd = _build_extract_command(
        archive_tool = archive_tool,
        archive_file = archive_file,
        extract_dir = extract_dir,
        password = password,
        skip_existing = skip_existing)

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

    # Decode Shift-JIS names
    return _decode_lzh_names(archive_file, extract_dir, verbose, pretend_run, exit_on_failure)

# Unpack an archive with tar, unrar, unar or 7-Zip by its type; False when nothing was extracted
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
    archive_tool = _get_extract_tool(archive_file)
    if not archive_tool:
        return False

    # Extract into destination
    extracted = _extract_into_directory(
        archive_tool = archive_tool,
        archive_file = archive_file,
        extract_dir = extract_dir,
        password = password,
        skip_existing = skip_existing,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not extracted:
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

# Whether 7-Zip's integrity test passes for the archive
def test_archive(
    archive_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = _find_archive_tool("7-Zip")
    if not archive_tool:
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

# Paths of the non-directory entries in 7-Zip's listing text
def _parse_archive_listing(list_text):
    all_paths = []
    for line in list_text.splitlines():
        pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (\S+)\s+(\d+)\s+(\d+)\s+(.+)$"
        match = re.match(pattern, line)
        if match:
            attr = match.group(1)
            path = match.group(4)
            if not attr.startswith("D.."):
                all_paths.append(path)
    return all_paths

# Longest paths first, dropping any path that is a parent of one already kept
def _condense_archive_paths(all_paths):
    condensed_paths = []
    for path in sorted(all_paths, key=lambda x: -len(x)):
        if not any(path + "/" == existing[:len(path) + 1] for existing in condensed_paths):
            condensed_paths.append(path)
    return condensed_paths

# File paths inside the archive from 7-Zip's listing, directories left out; empty without 7-Zip
def list_archive(
    archive_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = _find_archive_tool("7-Zip")
    if not archive_tool:
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
    all_paths = _parse_archive_listing(list_text)

    # Condense paths
    return _condense_archive_paths(all_paths)

###########################################################

# Extract each archive of the given types under the input path into a folder named after it,
# or into its own directory when same_dir is set
def extract_archives_by_type(input_path, archive_types, same_dir = False, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    archive_extensions = [archive_type.cval() for archive_type in archive_types]
    for file in paths.build_file_list_by_extensions(input_path, extensions = archive_extensions):

        # Get file info
        current_file = file
        file_dir = paths.get_filename_directory(current_file)
        file_basename = paths.get_filename_basename(current_file)
        output_dir = paths.join_paths(file_dir, file_basename)
        if same_dir:
            output_dir = file_dir

        # Decompress file
        extract_archive(
            archive_file = current_file,
            extract_dir = output_dir,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Whether the path ends with one of the comma-separated file types
def _has_listed_file_type(path, file_types):
    return any(path.endswith(file_type) for file_type in file_types.split(","))

# Archive each file directly in input_dir whose name ends with one of the comma-separated
# file types into an archive of the given type beside it, skipping files already archived
def archive_files_in_directory(
    input_dir,
    archive_type,
    file_types,
    password = None,
    volume_size = None,
    delete_originals = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for obj in paths.get_directory_contents(input_dir):
        obj_path = paths.join_paths(input_dir, obj)
        if not paths.is_path_file(obj_path):
            continue
        if not _has_listed_file_type(obj_path, file_types):
            continue
        output_file = paths.join_paths(input_dir, paths.get_filename_basename(obj_path) + archive_type.cval())
        if paths.does_path_exist(output_file):
            continue
        create_archive_from_file(
            archive_file = output_file,
            source_file = obj_path,
            password = password,
            volume_size = volume_size,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Archive each folder directly in input_dir into an archive of the given type named after it,
# skipping folders already archived
def archive_folders_in_directory(
    input_dir,
    archive_type,
    password = None,
    volume_size = None,
    delete_originals = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    for obj in paths.get_directory_contents(input_dir):
        obj_path = paths.join_paths(input_dir, obj)
        if not paths.is_path_directory(obj_path):
            continue
        output_file = paths.join_paths(input_dir, obj + archive_type.cval())
        if paths.does_path_exist(output_file):
            continue
        create_archive_from_folder(
            archive_file = output_file,
            source_dir = obj_path,
            password = password,
            volume_size = volume_size,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

###########################################################
# Deterministic rezipping
###########################################################

# Extract a zip beside itself, then zip the folder back in its place; quits when either step fails
def _rezip_archive(zip_file, verbose, pretend_run, exit_on_failure):
    zip_dir = paths.get_filename_directory(zip_file)
    zip_basename = paths.get_filename_basename(zip_file)
    extract_dir = paths.join_paths(zip_dir, zip_basename + "_extracted")

    # Unzip file
    logger.log_info("Unzipping file %s ..." % zip_file)
    success = extract_archive(
        archive_file = zip_file,
        extract_dir = extract_dir,
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to unzip file %s" % zip_file, quit_program = True)

    # Deterministically zip file
    logger.log_info("Deterministically rezipping ...")
    success = create_archive_from_folder(
        archive_file = zip_file,
        source_dir = extract_dir,
        delete_original = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        logger.log_error("Unable to rezip file %s" % zip_file, quit_program = True)

# Rezip every .zip under input_path deterministically, in place; quits on the first failure
def rezip_archives(input_path, verbose = False, pretend_run = False, exit_on_failure = False):
    for zip_file in paths.build_file_list_by_extensions(input_path, extensions = [".zip"]):
        _rezip_archive(zip_file, verbose, pretend_run, exit_on_failure)
