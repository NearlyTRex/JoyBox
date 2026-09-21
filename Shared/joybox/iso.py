# Imports
import os, os.path

# Local imports
import joybox.command as command
import joybox.logger as logger
import joybox.paths as paths
import joybox.fileops as fileops
import joybox.programs as programs
import joybox.archive as archive
from joybox import platform_info

# Check if iso is mounted
def is_iso_mounted(iso_file, mount_dir):
    return (
        paths.is_path_file(iso_file) and
        paths.does_path_exist(get_actual_mount_point(iso_file, mount_dir)) and
        not paths.is_directory_empty(mount_dir)
    )

# Get the iso tool
def get_iso_tool():
    if programs.is_tool_installed("XorrISO"):
        return programs.get_tool_program("XorrISO")
    logger.log_error("XorrISO was not found")
    return None

# Get the mount tool
def get_mount_tool():
    if programs.is_tool_installed("FuseISO"):
        return programs.get_tool_program("FuseISO")
    logger.log_error("FuseISO was not found")
    return None

# Get the unmount tool
def get_unmount_tool():
    if programs.is_tool_installed("FUserMount"):
        return programs.get_tool_program("FUserMount")
    logger.log_error("FUserMount was not found")
    return None

# Create iso
def create_iso(
    iso_file,
    source_dir = None,
    source_dirs = [],
    volume_name = None,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    iso_tool = get_iso_tool()
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
    if paths.is_path_valid(source_dir):
        create_command += [source_dir]
    for extra_source_dir in source_dirs:
        if paths.is_path_valid(extra_source_dir):
            create_command += [extra_source_dir]

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = command.create_command_options(
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
def extract_iso(
    iso_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source
    if not paths.is_path_file(iso_file):
        logger.log_error("Iso file '%s' was not found" % iso_file)
        return False

    # Try extracting as an archive first
    success = archive.extract_archive(
        archive_file = iso_file,
        extract_dir = extract_dir,
        delete_original = delete_original,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if success:
        return True

    # Get tool
    iso_tool = get_iso_tool()
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
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
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
    return paths.does_directory_contain_files(extract_dir)

# Extract an iso as a tree that can be built back into an iso
def extract_buildable_iso_tree(
    iso_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source
    if not paths.is_path_file(iso_file):
        logger.log_error("Iso file '%s' was not found" % iso_file)
        return False

    # Get tool
    iso_tool = get_iso_tool()
    if not iso_tool:
        return False

    # Make the destination
    success = fileops.make_directory(
        src = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
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
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to extract %s" % iso_file)
        return False

    # The extracted tree comes out read only
    fileops.chmod_file_or_directory(
        src = extract_dir,
        perms = 644,
        dperms = 755,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return True

# Get the efi boot image an extracted tree carries
def get_iso_efi_boot_image(extract_dir):
    return paths.join_paths(extract_dir, "efi.img")

# Extract the boot images an extracted tree does not carry as ordinary files
def extract_iso_boot_images(
    iso_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Already there
    if paths.is_path_file(get_iso_efi_boot_image(extract_dir)):
        return True

    # Get tool
    iso_tool = get_iso_tool()
    if not iso_tool:
        return False

    # Get extract command
    extract_cmd = [
        iso_tool,
        "-osirrox", "on",
        "-indev", iso_file,
        "-extract_boot_images", extract_dir
    ]

    # Run extract command
    code = command.run_returncode_command(
        cmd = extract_cmd,
        options = command.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to extract boot images from %s" % iso_file)
        return False
    if pretend_run:
        return True

    # The tool names what it extracted after the catalogue entry
    for candidate in sorted(paths.get_directory_contents(extract_dir)):
        if candidate.startswith("eltorito_img") and candidate.endswith(".img"):
            return fileops.move_file_or_directory(
                src = paths.join_paths(extract_dir, candidate),
                dest = get_iso_efi_boot_image(extract_dir),
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    logger.log_error("No efi boot image was found in %s" % extract_dir)
    return False

# Build the command that packs a tree as an iso that boots
def get_bootable_iso_command(
    iso_tool,
    iso_file,
    source_dir,
    volume_name = None,
    bios_boot_image = None,
    efi_boot_image = None):
    create_cmd = [
        iso_tool,
        "-as", "mkisofs",
        "-r",
        "-J", "-l",
    ]
    if volume_name:
        create_cmd += ["-V", volume_name]
    if bios_boot_image:
        create_cmd += [
            "-b", bios_boot_image,
            "-c", "boot.catalog",
            "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        ]
    if efi_boot_image:
        create_cmd += [
            "-eltorito-alt-boot",
            "-e", efi_boot_image,
            "-no-emul-boot",
            "-isohybrid-gpt-basdat",
        ]
    create_cmd += ["-o", iso_file, source_dir]
    return create_cmd

# Pack a tree as an iso that boots
def create_bootable_iso(
    iso_file,
    source_dir,
    volume_name = None,
    bios_boot_image = None,
    efi_boot_image = None,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    iso_tool = get_iso_tool()
    if not iso_tool:
        return False

    # Run create command
    code = command.run_returncode_command(
        cmd = get_bootable_iso_command(
            iso_tool = iso_tool,
            iso_file = iso_file,
            source_dir = source_dir,
            volume_name = volume_name,
            bios_boot_image = bios_boot_image,
            efi_boot_image = efi_boot_image),
        options = command.create_command_options(
            output_paths = [iso_file],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if code != 0:
        logger.log_error("Unable to package %s" % iso_file)
        return False
    if pretend_run:
        return True
    return paths.is_path_file(iso_file)

# Get actual mount point
def get_actual_mount_point(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Windows
    if platform_info.is_windows_platform():

        # Get drive command
        drive_cmd = [
            "powershell",
            "-Command", "Get-DiskImage",
            "-ImagePath", "\"" + iso_file + "\"",
            "|", "Get-Volume",
            "|", "Select-Object", "-ExpandProperty", "DriveLetter"
        ]

        # Run drive command
        drive_output = command.run_output_command(
            cmd = drive_cmd,
            options = command.create_command_options(
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
def mount_iso(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if is_iso_mounted(iso_file, mount_dir):
        return True

    # Make mount directories
    fileops.make_directory(
        src = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Windows
    if platform_info.is_windows_platform():

        # Get mount command
        mount_cmd = [
            "powershell",
            "-Command", "Mount-DiskImage",
            "-ImagePath", "\"" + iso_file + "\""
        ]

        # Run mount command
        code = command.run_returncode_command(
            cmd = mount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Linux
    elif platform_info.is_linux_platform():

        # Get tool
        iso_tool = get_mount_tool()
        if not iso_tool:
            return False

        # Get mount command
        mount_cmd = [
            iso_tool,
            iso_file,
            mount_dir
        ]

        # Run mount command
        code = command.run_returncode_command(
            cmd = mount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Check result
    return is_iso_mounted(iso_file, mount_dir)

# Unmount iso
def unmount_iso(
    iso_file,
    mount_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check if mounted
    if not is_iso_mounted(iso_file, mount_dir):
        return True

    # Windows
    if platform_info.is_windows_platform():

        # Get unmount command
        unmount_cmd = [
            "powershell",
            "-Command", "Dismount-DiskImage",
            "-ImagePath", "\"" + iso_file + "\""
        ]

        # Run unmount command
        code = command.run_returncode_command(
            cmd = unmount_cmd,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if code != 0:
            return False

    # Linux
    elif platform_info.is_linux_platform():

        # Get tool
        iso_tool = get_unmount_tool()
        if not iso_tool:
            return False

        # Get unmount command
        unmount_cmd = [
            iso_tool,
            "-u", mount_dir
        ]

        # Run unmount command
        code = command.run_returncode_command(
            cmd = unmount_cmd,
            options = command.create_command_options(
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
    return not is_iso_mounted(iso_file, mount_dir)
