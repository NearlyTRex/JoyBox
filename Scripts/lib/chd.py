# Imports
import os, os.path
import sys

# Local imports
import config
import fileops
import command
import programs
import system
import logger
import iso
import archive

# Get disc iso
def GetDiscISO(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.ISO.cval())

# Get disc toc
def GetDiscTOC(chd_file):
    return chd_file.replace(config.DiscImageFileType.CHD.cval(), config.DiscImageFileType.TOC.cval())

# Check if disc chd is mounted
def IsDiscCHDMounted(chd_file, mount_dir):
    return iso.IsISOMounted(
        iso_file = GetDiscISO(chd_file),
        mount_dir = mount_dir)

# Create disc chd
def CreateDiscCHD(
    chd_file,
    source_iso,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get create command
    create_command = [
        chd_tool,
        "createcd",
        "-i", source_iso,
        "-o", chd_file
    ]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = command.create_command_options(
            output_paths = [chd_file],
            blocking_processes = [chd_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = source_iso,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(chd_file)

# Extract disc chd
def ExtractDiscCHD(
    chd_file,
    binary_file,
    toc_file,
    force_overwrite = False,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get extract command
    extract_cmd = [
        chd_tool,
        "extractcd",
        "-i", chd_file,
        "-o", toc_file,
        "-ob", binary_file
    ]
    if force_overwrite:
        extract_cmd += ["--force"]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [toc_file, binary_file],
            blocking_processes = [chd_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(binary_file)

# Archive disc chd
def ArchiveDiscCHD(
    chd_file,
    zip_file,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Create temporary directory
    tmp_dir_success, tmp_dir_result = fileops.create_temporary_directory(
        verbose = verbose,
        pretend_run = pretend_run)
    if not tmp_dir_success:
        return False

    # Mount chd
    success = MountDiscCHD(
        chd_file = chd_file,
        mount_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Archive contents
    success = archive.CreateArchiveFromFolder(
        archive_file = zip_file,
        source_dir = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = chd_file,
            verbose = verbose,
            pretend_run = pretend_run)
    fileops.remove_directory(
        src = tmp_dir_result,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return os.path.exists(zip_file)

# Verify disc chd
def VerifyDiscCHD(
    chd_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    chd_tool = None
    if programs.is_tool_installed("MameChdman"):
        chd_tool = programs.get_tool_program("MameChdman")
    if not chd_tool:
        logger.log_error("MameChdman was not found")
        return False

    # Get verify command
    verify_cmd = [
        chd_tool,
        "verify",
        "-i", chd_file
    ]

    # Run verify command
    verify_output = command.run_output_command(
        cmd = verify_cmd,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check verification
    verify_text = verify_output
    if isinstance(verify_output, bytes):
        verify_text = verify_output.decode()
    return "Overall SHA1 verification successful!" in verify_text

# Mount disc chd
def MountDiscCHD(
    chd_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if IsDiscCHDMounted(chd_file, mount_dir):
        return True

    # Extract iso from chd
    success = ExtractDiscCHD(
        chd_file = chd_file,
        binary_file = GetDiscISO(chd_file),
        toc_file = GetDiscTOC(chd_file),
        force_overwrite = True,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Mount iso
    success = iso.MountISO(
        iso_file = GetDiscISO(chd_file),
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return IsDiscCHDMounted(chd_file, mount_dir)

# Unmount disc chd
def UnmountDiscCHD(
    chd_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if not IsDiscCHDMounted(chd_file, mount_dir):
        return True

    # Unmount iso
    success = iso.UnmountISO(
        iso_file = GetDiscISO(chd_file),
        mount_dir = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Check result
    return not IsDiscCHDMounted(chd_file, mount_dir)
