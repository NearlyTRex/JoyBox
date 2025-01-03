# Imports
import os
import os.path
import sys
import zipfile

# Local imports
import config
import command
import programs
import system
import environment
import sandbox

# Get archive extension
def GetArchiveExtension(archive_type):
    return config.ArchiveType.to_lower_string(archive_type)

# Determine if file is a known archive
def IsKnownArchive(archive_file, extensions = [], mime_types = []):
    for ext in extensions:
        if archive_file.lower().endswith(ext.lower()):
            return True
    actual_mime_type = system.GetFileMimeType(archive_file)
    for potential_mime_type in mime_types:
        if potential_mime_type.lower() in actual_mime_type.lower():
            return True
    return False

# Determine if file is an archive
def IsArchive(archive_file):
    if IsZipArchive(archive_file):
        return True
    elif Is7zArchive(archive_file):
        return True
    elif IsTarballArchive(archive_file):
        return True
    elif IsExeArchive(archive_file):
        return True
    elif IsAppImageArchive(archive_file):
        return True
    return False

# Determine if file is a zip archive
def IsZipArchive(archive_file):
    return IsKnownArchive(
        archive_file = archive_file,
        extensions = config.computer_archive_extensions_zip,
        mime_types = config.mime_types_zip)

# Determine if file is a 7z archive
def Is7zArchive(archive_file):
    return IsKnownArchive(
        archive_file = archive_file,
        extensions = config.computer_archive_extensions_7z,
        mime_types = config.mime_types_7z)

# Determine if file is a tarball archive
def IsTarballArchive(archive_file):
    return IsKnownArchive(
        archive_file = archive_file,
        extensions = config.computer_archive_extensions_tarball,
        mime_types = config.mime_types_tarball)

# Determine if file is an exe archive
def IsExeArchive(archive_file):
    return IsKnownArchive(
        archive_file = archive_file,
        extensions = config.computer_archive_extensions_exe,
        mime_types = config.mime_types_exe)

# Determine if file is an appimage archive
def IsAppImageArchive(archive_file):
    return IsKnownArchive(
        archive_file = archive_file,
        extensions = config.computer_archive_extensions_appimage,
        mime_types = config.mime_types_appimage)

# Check archive checksums
def GetArchiveChecksums(archive_file):
    checksums = []
    if IsZipArchive(archive_file):
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
def GetArchiveCompressionFlags(archive_type, password, volume_size):
    compression_flags = []
    if archive_type == config.ArchiveType.ZIP:
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
    elif archive_type == config.ArchiveType.SEVENZIP:
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
def CheckArchiveCompressionOutputFiles(
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
            system.MoveFileOrDirectory(
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
def CreateArchiveFromFile(
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
    if programs.IsToolInstalled("7-Zip"):
        archive_tool = programs.GetToolProgram("7-Zip")
    if not archive_tool:
        system.LogError("7-Zip was not found")
        return False

    # Get archive type
    archive_type = None
    if IsZipArchive(archive_file):
        archive_type = config.ArchiveType.ZIP
    elif Is7zArchive(archive_file):
        archive_type = config.ArchiveType.SEVENZIP
    if not archive_type:
        system.LogError("Unrecognized archive type for %s" % archive_file)
        return False

    # Get path to add
    path_to_add = sandbox.TranslatePathIfNecessary(
        path = source_file,
        program_exe = archive_tool,
        program_name = "7-Zip")

    # Get create command
    create_command = [
        archive_tool,
        "a"
    ]
    create_command += GetArchiveCompressionFlags(
        archive_type = archive_type,
        password = password,
        volume_size = volume_size)
    create_command += [
        archive_file,
        path_to_add
    ]

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_command,
        options = command.CommandOptions(
            cwd = system.GetFilenameDirectory(source_file),
            output_paths = [archive_file],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(
            file = source_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check output files
    return CheckArchiveCompressionOutputFiles(
        archive_file = archive_file,
        archive_type = archive_type,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Create archive from folder
def CreateArchiveFromFolder(
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
    if programs.IsToolInstalled("7-Zip"):
        archive_tool = programs.GetToolProgram("7-Zip")
    if not archive_tool:
        system.LogError("7-Zip was not found")
        return False

    # Get archive type
    archive_type = None
    if IsZipArchive(archive_file):
        archive_type = config.ArchiveType.ZIP
    elif Is7zArchive(archive_file):
        archive_type = config.ArchiveType.SEVENZIP
    if not archive_type:
        system.LogError("Unrecognized archive type for %s" % archive_file)
        return False

    # Create list of objects to add
    objs_to_add = []
    for obj in system.GetDirectoryContents(source_dir):
        if obj in excludes:
            continue
        path_to_add = sandbox.TranslatePathIfNecessary(
            path = os.path.join(source_dir, obj),
            program_exe = archive_tool,
            program_name = "7-Zip")
        objs_to_add.append(path_to_add)

    # Get create command
    create_command = [
        archive_tool,
        "a"
    ]
    create_command += GetArchiveCompressionFlags(
        archive_type = archive_type,
        password = password,
        volume_size = volume_size)
    create_command += [
        archive_file
    ]
    create_command += objs_to_add

    # Run create command
    code = command.RunBlockingCommand(
        cmd = create_command,
        options = command.CommandOptions(
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
        system.RemoveDirectory(
            dir = source_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check output files
    return CheckArchiveCompressionOutputFiles(
        archive_file = archive_file,
        archive_type = archive_type,
        volume_size = volume_size,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract archive
def ExtractArchive(
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
    if IsTarballArchive(archive_file):
        if programs.IsToolInstalled("Tar"):
            archive_tool = programs.GetToolProgram("Tar")
        if not archive_tool:
            system.LogError("Tar was not found")
            return False
    else:
        if programs.IsToolInstalled("7-Zip"):
            archive_tool = programs.GetToolProgram("7-Zip")
        if not archive_tool:
            system.LogError("7-Zip was not found")
            return False

    # Get extract command
    extract_cmd = []
    if IsTarballArchive(archive_file):
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
    code = command.RunBlockingCommand(
        cmd = extract_cmd,
        options = command.CommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [archive_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        system.RemoveFile(
            file = archive_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir) and not system.IsDirectoryEmpty(extract_dir)

# Test archive
def TestArchive(
    archive_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    archive_tool = None
    if programs.IsToolInstalled("7-Zip"):
        archive_tool = programs.GetToolProgram("7-Zip")
    if not archive_tool:
        system.LogError("7-Zip was not found")
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
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return (code == 0)
