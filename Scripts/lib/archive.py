# Imports
import os
import os.path
import sys
import zipfile

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
import config
import command
import programs
import system
import environment
import sandbox

# Determine if file is an archive
def IsArchive(archive_file):
    for ext in config.computer_archive_extensions:
        if archive_file.endswith(ext):
            return True
    return False

# Determine if file is a tarball archive
def IsTarballArchive(archive_file):
    for ext in config.computer_archive_extensions_tarball:
        if archive_file.endswith(ext):
            return True
    return False

# Check archive checksums
def GetArchiveChecksums(archive_file):
    checksums = []
    with zipfile.ZipFile(archive_file) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            entry = {}
            entry["path"] = info.filename
            entry["crc"] = hex(info.CRC)
            checksums.append(entry)
    return checksums

# Create zip from file
def CreateZipFromFile(zip_file, source_file, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    archive_tool = None
    if command.IsRunnableCommand(programs.GetToolProgram("7-Zip-Standalone")):
        archive_tool = programs.GetToolProgram("7-Zip-Standalone")
    if not archive_tool:
        return False

    # Get path to add
    path_to_add = sandbox.TranslatePathIfNecessary(
        path = source_file,
        program_exe = archive_tool,
        program_name = "7-Zip-Standalone")

    # Get create command
    create_command = [
        archive_tool,
        "a",
        "-tzip", # Archive format
        "-bb3", # Show files being added
        "-mx=7", # Compression level
        "-mm=Deflate", # Compression method
        "-mtc=off", # Do no store NTFS timestamps for files
        "-mcu=on", # Use UTF-8 for file names that contain non-ASCII symbols
        "-mmt=on", # Use multithreading
        "-ma=1", # Reproducible archive
        zip_file,
        path_to_add
    ]

    # Run create command
    command.RunBlockingCommand(
        cmd = create_command,
        options = command.CommandOptions(
            cwd = system.GetFilenameDirectory(source_file),
            output_paths = [zip_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(source_file, verbose = verbose)

    # Check result
    return os.path.exists(zip_file)

# Create zip from folder
def CreateZipFromFolder(zip_file, source_dir, excludes = [], delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    archive_tool = None
    if command.IsRunnableCommand(programs.GetToolProgram("7-Zip-Standalone")):
        archive_tool = programs.GetToolProgram("7-Zip-Standalone")
    if not archive_tool:
        return False

    # Create list of objects to add
    objs_to_add = []
    for obj in system.GetDirectoryContents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandbox.TranslatePathIfNecessary(
            path = os.path.join(source_dir, obj),
            program_exe = archive_tool,
            program_name = "7-Zip-Standalone")
        objs_to_add.append(path_to_add)

    # Get create command
    create_command = [
        archive_tool,
        "a",
        "-tzip", # Archive format
        "-bb3", # Show files being added
        "-mx=7", # Compression level
        "-mm=Deflate", # Compression method
        "-mtc=off", # Do no store NTFS timestamps for files
        "-mcu=on", # Use UTF-8 for file names that contain non-ASCII symbols
        "-mmt=on", # Use multithreading
        "-ma=1", # Reproducible archive
        zip_file
    ]
    create_command += objs_to_add

    # Run create command
    command.RunBlockingCommand(
        cmd = create_command,
        options = command.CommandOptions(
            cwd = source_dir,
            output_paths = [zip_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveDirectory(source_dir, verbose = verbose)

    # Check result
    return os.path.exists(zip_file)

# Create exe from folder
def CreateExeFromFolder(exe_file, source_dir, excludes = [], delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    archive_tool = None
    if command.IsRunnableCommand(programs.GetToolProgram("7-Zip-Standalone")):
        archive_tool = programs.GetToolProgram("7-Zip-Standalone")
    if not archive_tool:
        return False

    # Create list of objects to add
    objs_to_add = []
    for obj in system.GetDirectoryContents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandbox.TranslatePathIfNecessary(
            path = os.path.join(source_dir, obj),
            program_exe = archive_tool,
            program_name = "7-Zip-Standalone")
        objs_to_add.append(path_to_add)

    # Get create command
    create_command = [
        archive_tool,
        "a",
        "-bb3", # Show files being added
        "-mx=7", # Compression level
        "-mmt=on", # Use multithreading
        "-ma=1", # Reproducible archive
        "-sfx7z.sfx", # Make self extracting
        exe_file
    ]
    create_command += objs_to_add

    # Run create command
    command.RunBlockingCommand(
        cmd = create_command,
        options = command.CommandOptions(
            cwd = source_dir,
            output_paths = [exe_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveDirectory(source_dir, verbose = verbose)

    # Check result
    return os.path.exists(exe_file)

# Extract archive
def ExtractArchive(archive_file, extract_dir, skip_existing = False, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    archive_tool = None
    if command.IsRunnableCommand(programs.GetToolProgram("7-Zip")):
        archive_tool = programs.GetToolProgram("7-Zip")
    if not archive_tool:
        return False

    # Get extract command
    extract_cmd = [
        archive_tool,
        "x",
        archive_file,
        "-o" + extract_dir,
        "-bb3"
    ]
    if skip_existing:
        extract_cmd += ["-aos"]
    else:
        extract_cmd += ["-aoa"]

    # Update command for tarball archives
    if IsTarballArchive(archive_file):
        if environment.IsLinuxPlatform():
            extract_cmd = [
                "tar",
                "xvf",
                archive_file,
                "-C", extract_dir
            ]

    # Run extract command
    command.RunBlockingCommand(
        cmd = extract_cmd,
        options = command.CommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(archive_file, verbose = verbose)

    # Check result
    return os.path.exists(extract_dir) and not system.IsDirectoryEmpty(extract_dir)

# Test archive
def TestArchive(archive_file, verbose = False, exit_on_failure = False):

    # Get tool
    archive_tool = None
    if command.IsRunnableCommand(programs.GetToolProgram("7-Zip-Standalone")):
        archive_tool = programs.GetToolProgram("7-Zip-Standalone")
    if not archive_tool:
        return False

    # Get test command
    test_cmd = [
        archive_tool,
        "t",
        archive_file
    ]

    # Run test command
    code = command.RunBlockingCommand(
        cmd = test_cmd,
        options = command.CommandOptions(
            blocking_processes = [archive_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    return (code == 0)
