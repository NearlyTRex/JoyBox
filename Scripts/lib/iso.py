# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import logger
import paths
import environment
import fileops
import programs
import sandbox
import registry
import archive

# Check if iso is mounted
def IsISOMounted(iso_file, mount_dir):
    return (
        paths.is_path_file(iso_file) and
        paths.does_path_exist(GetActualMountPoint(iso_file, mount_dir)) and
        not paths.is_directory_empty(mount_dir)
    )

# Create iso
def CreateISO(
    iso_file,
    source_dir = None,
    source_dirs = [],
    volume_name = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    iso_tool = None
    if programs.IsToolInstalled("XorrISO"):
        iso_tool = programs.GetToolProgram("XorrISO")
    if not iso_tool:
        logger.log_error("XorrISO was not found")
        return False

    # Get create command
    create_command = [
        iso_tool,
        "-preparer_id", "xorriso",
        "-as", "mkisofs",
        "-iso-level", "3",
        "-graft-points",
        "-full-iso9660-filenames",
        "-joliet",
        "-o", iso_file
    ]

    if volume_name:
        create_command += ["-volid", volume_name]
    if paths.is_path_valid(source_dir):
        create_command += [source_dir]

    # Run create command
    code = command.RunReturncodeCommand(
        cmd = create_command,
        options = command.CreateCommandOptions(
            output_paths = [iso_file],
            blocking_processes = [iso_tool]),
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

    # Check result
    return os.path.exists(iso_file)

# Extract iso
def ExtractISO(
    iso_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Try extracting as an archive first
    success = archive.ExtractArchive(
        archive_file = iso_file,
        extract_dir = extract_dir,
        delete_original = delete_original,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if success:
        return True

    # Get tool
    iso_tool = None
    if programs.IsToolInstalled("XorrISO"):
        iso_tool = programs.GetToolProgram("XorrISO")
    if not iso_tool:
        logger.log_error("XorrISO was not found")
        return False

    # Get extract command
    extract_cmd = [
        iso_tool,
        "-osirrox", "on",
        "-indev", iso_file,
        "-extract", "/",
        extract_dir
    ]

    # Run extract command
    code = command.RunReturncodeCommand(
        cmd = extract_cmd,
        options = command.CreateCommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Reset permissions on extracted files
    fileops.chmod_file_or_directory(
        src = extract_dir,
        perms = 666,
        dperms = 777,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = iso_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir)

# Get actual mount point
def GetActualMountPoint(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Windows
    if environment.is_windows_platform():

        # Get drive command
        drive_cmd = [
            "powershell",
            "-Command", "Get-DiskImage",
            "-ImagePath", "\"" + iso_file + "\"",
            "|", "Get-Volume",
            "|", "Select-Object", "-ExpandProperty", "DriveLetter"
        ]

        # Run drive command
        drive_output = command.RunOutputCommand(
            cmd = drive_cmd,
            options = command.CreateCommandOptions(
                is_shell=True),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get drive letter
        drive_text = drive_output
        if isinstance(drive_output, bytes):
            drive_text = drive_output.decode()
        if drive_text:
            return f"{drive_text}:\\"
        else:
            return None

    # Mount point matches expectations
    return mount_dir

# Mount iso
def MountISO(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if IsISOMounted(iso_file, mount_dir):
        return True

    # Make mount directories
    fileops.make_directory(
        src = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Windows
    if environment.is_windows_platform():

        # Get mount command
        mount_cmd = [
            "powershell",
            "-Command", "Mount-DiskImage",
            "-ImagePath", "\"" + iso_file + "\""
        ]

        # Run mount command
        code = command.RunReturncodeCommand(
            cmd = mount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Linux
    elif environment.is_linux_platform():

        # Get tool
        iso_tool = None
        if programs.IsToolInstalled("FuseISO"):
            iso_tool = programs.GetToolProgram("FuseISO")
        if not iso_tool:
            logger.log_error("FuseISO was not found")
            return False

        # Get mount command
        mount_cmd = [
            iso_tool,
            iso_file,
            mount_dir
        ]

        # Run mount command
        code = command.RunReturncodeCommand(
            cmd = mount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Check result
    return IsISOMounted(iso_file, mount_dir)

# Unmount iso
def UnmountISO(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if not IsISOMounted(iso_file, mount_dir):
        return True

    # Windows
    if environment.is_windows_platform():

        # Get unmount command
        unmount_cmd = [
            "powershell",
            "-Command", "Dismount-DiskImage",
            "-ImagePath", "\"" + iso_file + "\""
        ]

        # Run unmount command
        code = command.RunReturncodeCommand(
            cmd = unmount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Linux
    elif environment.is_linux_platform():

        # Get tool
        iso_tool = None
        if programs.IsToolInstalled("FUserMount"):
            iso_tool = programs.GetToolProgram("FUserMount")
        if not iso_tool:
            logger.log_error("FUserMount was not found")
            return False

        # Get unmount command
        unmount_cmd = [
            iso_tool,
            "-u", mount_dir
        ]

        # Run unmount command
        code = command.RunReturncodeCommand(
            cmd = unmount_cmd,
            options = command.CreateCommandOptions(
                blocking_processes = [iso_tool]),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Remove mount point
    fileops.remove_directory(
        src = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return not IsISOMounted(iso_file, mount_dir)
