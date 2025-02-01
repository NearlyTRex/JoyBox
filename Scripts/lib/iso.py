# Imports
import os, os.path
import sys

# Local imports
import config
import command
import system
import environment
import programs
import sandbox
import registry
import archive

# Check if iso is mounted
def IsISOMounted(iso_file, mount_dir):
    return (
        system.IsPathFile(iso_file) and
        system.IsPathDirectory(mount_dir) and
        not system.IsDirectoryEmpty(mount_dir)
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
        system.LogError("XorrISO was not found")
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
    if system.IsPathValid(source_dir):
        create_command += [source_dir]

    # Run create command
    command.RunBlockingCommand(
        cmd = create_command,
        options = command.CreateCommandOptions(
            output_paths = [iso_file],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveDirectory(
            dir = source_dir,
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

    # Get tool
    iso_tool = None
    if programs.IsToolInstalled("XorrISO"):
        iso_tool = programs.GetToolProgram("XorrISO")
    if not iso_tool:
        system.LogError("XorrISO was not found")
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
    command.RunBlockingCommand(
        cmd = extract_cmd,
        options = command.CreateCommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Reset permissions on extracted files
    system.ChmodFileOrDirectory(
        src = extract_dir,
        perms = 666,
        dperms = 777,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(
            file = iso_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(extract_dir)

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
    system.MakeDirectory(
        dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Extract files to mount point
    success = ExtractISO(
        iso_file = iso_file,
        extract_dir = mount_dir,
        delete_original = False,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
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

    # Remove mount point
    system.RemoveDirectory(
        dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return not IsISOMounted(iso_file, mount_dir)
