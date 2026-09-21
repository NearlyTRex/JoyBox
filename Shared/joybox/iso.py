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

# Get the path the master boot record of an image is extracted to
def get_iso_mbr_image(extract_dir):
    return paths.join_paths(extract_dir, "mbr.img")

# Extract the boot images an extracted tree does not carry as ordinary files
# Size of an iso block, and of the sectors el torito counts a load size in
iso_block_size = 2048
el_torito_sector_size = 512

# The boot code lives in the system area at the very front of an image, ahead
# of the filesystem, and is not reachable as a file.
iso_mbr_sectors = 16

# Partition types a hybrid image is assembled with: the appended efi system
# partition, and the type the iso filesystem itself is declared as.
efi_partition_type = "28732ac11ff8d211ba4b00a0c93ec93b"
iso_mbr_partition_type = "a2a0d0ebe5b9334487c068b6b72699c7"

# Read the el torito catalogue of an image
def get_iso_boot_report(
    iso_file,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    iso_tool = get_iso_tool()
    if not iso_tool:
        return None
    return command.run_output_command(
        cmd = [iso_tool, "-indev", iso_file, "-report_el_torito", "plain"],
        options = command.create_command_options(blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Find where the efi boot image sits inside an image
# It is a hidden el torito entry rather than a file in the tree, so there is
# nothing to copy out by path. The catalogue gives its start and its length,
# and the entry is read out of the image itself.
def get_efi_boot_image_extent(report):
    if not report:
        return None
    if isinstance(report, bytes):
        report = report.decode("utf-8", "replace")

    # El Torito boot img :   N  UEFI  y   none  0x0000  0x00  10296     1426880
    # The label carries its own colon, so the columns are read from what
    # follows the separator rather than counted from the start of the line.
    entry = None
    for line in report.splitlines():
        if not line.startswith("El Torito boot img") or ":" not in line:
            continue
        fields = line.split(":", 1)[1].split()
        if "UEFI" not in fields or len(fields) < 3:
            continue
        try:
            entry = (fields[0], int(fields[-2]), int(fields[-1]))
        except ValueError:
            continue
        break
    if not entry:
        return None
    number, load_size, block = entry

    # El Torito img blks :   2  2574
    # The load size is counted in 512 byte sectors, so the catalogue's own
    # count of iso blocks is preferred where it is given.
    for line in report.splitlines():
        if not line.startswith("El Torito img blks") or ":" not in line:
            continue
        fields = line.split(":", 1)[1].split()
        if len(fields) >= 2 and fields[0] == number:
            try:
                return block, int(fields[1])
            except ValueError:
                break
    if load_size <= 0:
        return None
    blocks = load_size * el_torito_sector_size
    return block, (blocks + iso_block_size - 1) // iso_block_size

# Copy a run of bytes out of an image
def copy_iso_extent(iso_file, output_file, offset, length):
    try:
        with open(iso_file, "rb") as source:
            source.seek(offset)
            with open(output_file, "wb") as target:
                remaining = length
                while remaining > 0:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        break
                    target.write(chunk)
                    remaining -= len(chunk)
                return remaining == 0
    except Exception as e:
        logger.log_error("Unable to read boot data from %s" % iso_file)
        logger.log_error(e)
        return False

# Extract the boot data of an image
# Neither the efi image nor the boot code is in the filesystem tree, so a
# rebuild from the tree alone produces an image that boots on nothing.
def extract_iso_boot_images(
    iso_file,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Already there
    output_file = get_iso_efi_boot_image(extract_dir)
    mbr_file = get_iso_mbr_image(extract_dir)
    if paths.is_path_file(output_file) and paths.is_path_file(mbr_file):
        return True

    # Find it in the catalogue
    report = get_iso_boot_report(
        iso_file = iso_file,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if pretend_run:
        return True
    extent = get_efi_boot_image_extent(report)
    if not extent:
        logger.log_error("No efi boot image was found in %s" % iso_file)
        return False

    # Read it out of the image
    block, blocks = extent
    if verbose:
        logger.log_info("Extracting efi boot image from %s" % iso_file)
    if not copy_iso_extent(
        iso_file, output_file, block * iso_block_size, blocks * iso_block_size):
        logger.log_error("Unable to extract boot images from %s" % iso_file)
        return False

    # Take the boot code with it. Without it the rebuilt image has no
    # partition table at all, which boots from a disc and from nothing else.
    if verbose:
        logger.log_info("Extracting boot code from %s" % iso_file)
    if not copy_iso_extent(
        iso_file, mbr_file, 0, iso_mbr_sectors * el_torito_sector_size):
        logger.log_error("Unable to extract boot code from %s" % iso_file)
        return False
    return True

# Build the command that packs a tree as an iso that boots
# Build the command that packs a tree as an iso that boots
# An image that only carries an el torito catalogue boots from a disc. To
# boot from a usb stick it also needs a partition table describing the same
# data, so the efi image is appended as a real partition and the boot code is
# put back in the system area.
def get_bootable_iso_command(
    iso_tool,
    iso_file,
    source_dir,
    volume_name = None,
    bios_boot_image = None,
    efi_boot_image = None,
    mbr_image = None):
    create_cmd = [
        iso_tool,
        "-as", "mkisofs",
        "-r",
        "-J", "-l",
    ]
    if volume_name:
        create_cmd += ["-V", volume_name]
    if mbr_image:
        create_cmd += [
            "--grub2-mbr", mbr_image,
            "--protective-msdos-label",
            "-partition_cyl_align", "off",
            "-partition_offset", "16",
            "--mbr-force-bootable",
        ]
    if efi_boot_image:
        create_cmd += [
            "-append_partition", "2", efi_partition_type, efi_boot_image,
            "-appended_part_as_gpt",
            "-iso_mbr_part_type", iso_mbr_partition_type,
        ]
    if bios_boot_image:
        create_cmd += [
            "-b", bios_boot_image,
            "-c", "boot.catalog",
            "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
            "--grub2-boot-info",
        ]
    if efi_boot_image:

        # The catalogue entry points at the appended partition rather than at
        # a file, so the same bytes serve both ways of booting.
        create_cmd += [
            "-eltorito-alt-boot",
            "-e", "--interval:appended_partition_2:all::",
            "-no-emul-boot",
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
    mbr_image = None,
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
            efi_boot_image = efi_boot_image,
            mbr_image = mbr_image),
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
