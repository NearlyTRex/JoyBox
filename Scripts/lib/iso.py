# Imports
import os, os.path
import sys

# Custom imports
lib_folder = os.path.realpath(os.path.dirname(__file__))
sys.path.append(lib_folder)
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
        os.path.isfile(iso_file) and
        os.path.isdir(mount_dir) and
        not system.IsDirectoryEmpty(mount_dir)
    )

# Create iso
def CreateISO(iso_file, source_dir = None, source_dirs = [], volume_name = None, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    iso_tool = None
    if command.IsRunnableCommand(config.default_xorriso_exe, config.default_xorriso_install_dirs):
        iso_tool = command.GetRunnableCommandPath(config.default_xorriso_exe, config.default_xorriso_install_dirs)
    if not iso_tool:
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
        options = command.CommandOptions(
            output_paths = [iso_file],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveDirectory(source_dir)

    # Check result
    return os.path.exists(iso_file)

# Extract iso
def ExtractISO(iso_file, extract_dir, delete_original = False, verbose = False, exit_on_failure = False):

    # Get tool
    iso_tool = None
    if command.IsRunnableCommand(config.default_xorriso_exe, config.default_xorriso_install_dirs):
        iso_tool = command.GetRunnableCommandPath(config.default_xorriso_exe, config.default_xorriso_install_dirs)
    if not iso_tool:
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
        options = command.CommandOptions(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Clean up
    if delete_original:
        system.RemoveFile(iso_file)

    # Check result
    return os.path.exists(extract_dir)

# Mount iso
def MountISO(iso_file, mount_dir, verbose = False, exit_on_failure = False):

    # Check if mounted
    if IsISOMounted(iso_file, mount_dir):
        return True

    # Make mount directories
    system.MakeDirectory(mount_dir, verbose = verbose, exit_on_failure = exit_on_failure)

    # Extract files to mount point
    success = ExtractISO(
        iso_file = iso_file,
        extract_dir = mount_dir,
        delete_original = False,
        verbose = verbose,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return IsISOMounted(iso_file, mount_dir)

# Unmount iso
def UnmountISO(iso_file, mount_dir, verbose = False, exit_on_failure = False):

    # Check if mounted
    if not IsISOMounted(iso_file, mount_dir):
        return True

    # Remove mount point
    system.RemoveDirectory(
        dir = mount_dir,
        verbose = verbose,
        exit_on_failure = exit_on_failure)

    # Check result
    return not IsISOMounted(iso_file, mount_dir)
