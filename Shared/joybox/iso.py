# Imports
import os
import os.path

# Local imports
from joybox import config
from joybox import command
from joybox import commandbase
from joybox import logger
from joybox import serialization
from joybox import paths
from joybox import fileops
from joybox import programs
from joybox import archive
from joybox import hfs
from joybox import platform_info

# Check if iso is mounted
def is_iso_mounted(iso_file, mount_dir):
    if not paths.is_path_file(iso_file):
        return False
    mount_point = get_actual_mount_point(iso_file, mount_dir)
    return (
        paths.does_path_exist(mount_point) and
        not paths.is_directory_empty(mount_point)
    )

# The XorrISO program path; None, logging an error, when it is not installed
def get_iso_tool():
    if programs.is_tool_installed("XorrISO"):
        return programs.get_tool_program("XorrISO")
    logger.log_error("XorrISO was not found")
    return None

# The FuseISO program path; None, logging an error, when it is not installed
def get_mount_tool():
    if programs.is_tool_installed("FuseISO"):
        return programs.get_tool_program("FuseISO")
    logger.log_error("FuseISO was not found")
    return None

# The FUserMount program path; None, logging an error, when it is not installed
def get_unmount_tool():
    if programs.is_tool_installed("FUserMount"):
        return programs.get_tool_program("FUserMount")
    logger.log_error("FUserMount was not found")
    return None

# The xorriso mkisofs command packing the valid source folders as an ISO 9660 + Joliet image
def _get_create_iso_command(iso_tool, iso_file, source_dir, source_dirs, volume_name):
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
    return create_command

# Build an ISO 9660 + Joliet image from one or more folders with xorriso, optionally deleting the source folder; True when the image exists
def create_iso(
    iso_file,
    source_dir = None,
    source_dirs = (),
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
    create_command = _get_create_iso_command(iso_tool, iso_file, source_dir, source_dirs, volume_name)

    # Run create command
    code = command.run_returncode_command(
        cmd = create_command,
        options = commandbase.create_command_options(
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

# Extract the whole iso into extract_dir with xorriso's osirrox; True when it exits cleanly
def _run_xorriso_extract(iso_tool, iso_file, extract_dir, verbose, pretend_run, exit_on_failure):
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
        options = commandbase.create_command_options(
            output_paths = [extract_dir],
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Extract an iso as an archive, falling back to xorriso with permissions opened to 666/777; True when the folder ends up with files
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
    return _extract_iso_with_xorriso(iso_file, extract_dir, delete_original, verbose, pretend_run, exit_on_failure)

# Extract an iso with xorriso, opening permissions to 666/777 and optionally deleting the
# image; True when the folder ends up with files
def _extract_iso_with_xorriso(iso_file, extract_dir, delete_original, verbose, pretend_run, exit_on_failure):

    # Get tool
    iso_tool = get_iso_tool()
    if not iso_tool:
        return False

    # Run extract command
    if not _run_xorriso_extract(iso_tool, iso_file, extract_dir, verbose, pretend_run, exit_on_failure):
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

    # Run extract command
    if not _run_xorriso_extract(iso_tool, iso_file, extract_dir, verbose, pretend_run, exit_on_failure):
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
ISO_BLOCK_SIZE = 2048
EL_TORITO_SECTOR_SIZE = 512

# The boot code lives in the system area at the very front of an image, ahead
# of the filesystem, and is not reachable as a file.
ISO_MBR_SECTORS = 16

# Partition types a hybrid image is assembled with: the appended efi system
# partition, and the type the iso filesystem itself is declared as.
EFI_PARTITION_TYPE = "28732ac11ff8d211ba4b00a0c93ec93b"
ISO_MBR_PARTITION_TYPE = "a2a0d0ebe5b9334487c068b6b72699c7"

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
        options = commandbase.create_command_options(blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# (number, load size, start block) of the catalogue's first UEFI boot image entry; None
# when there is none
def _find_efi_boot_entry(report):

    # El Torito boot img :   N  UEFI  y   none  0x0000  0x00  10296     1426880
    # The label carries its own colon, so the columns are read from what
    # follows the separator rather than counted from the start of the line.
    for line in report.splitlines():
        if not line.startswith("El Torito boot img") or ":" not in line:
            continue
        fields = line.split(":", 1)[1].split()
        if "UEFI" not in fields or len(fields) < 3:
            continue
        try:
            return (fields[0], int(fields[-2]), int(fields[-1]))
        except ValueError:
            continue
    return None

# Find where the efi boot image sits inside an image: a hidden el torito entry,
# not a file in the tree, so its start and length come from the catalogue
def get_efi_boot_image_extent(report):
    if not report:
        return None
    if isinstance(report, bytes):
        report = report.decode("utf-8", "replace")

    # Find the UEFI boot image entry
    entry = _find_efi_boot_entry(report)
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
    blocks = load_size * EL_TORITO_SECTOR_SIZE
    return block, (blocks + ISO_BLOCK_SIZE - 1) // ISO_BLOCK_SIZE

# Copy a run of bytes out of an image
def copy_iso_extent(iso_file, output_file, offset, length):
    if serialization.copy_binary_range(iso_file, output_file, offset, length):
        return True
    logger.log_error("Unable to read boot data from %s" % iso_file)
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

    # Read it and the boot code out of the image
    return _copy_iso_boot_images(iso_file, output_file, mbr_file, extent, verbose)

# Copy the efi boot image's (block, blocks) extent and the boot code out of the image
def _copy_iso_boot_images(iso_file, output_file, mbr_file, extent, verbose):

    # Read it out of the image
    block, blocks = extent
    if verbose:
        logger.log_info("Extracting efi boot image from %s" % iso_file)
    if not copy_iso_extent(
        iso_file, output_file, block * ISO_BLOCK_SIZE, blocks * ISO_BLOCK_SIZE):
        logger.log_error("Unable to extract boot images from %s" % iso_file)
        return False

    # Take the boot code with it. Without it the rebuilt image has no
    # partition table at all, which boots from a disc and from nothing else.
    if verbose:
        logger.log_info("Extracting boot code from %s" % iso_file)
    if not copy_iso_extent(
        iso_file, mbr_file, 0, ISO_MBR_SECTORS * EL_TORITO_SECTOR_SIZE):
        logger.log_error("Unable to extract boot code from %s" % iso_file)
        return False
    return True

# Arguments putting the boot code in the system area and appending the efi image as a gpt
# partition, for whichever of the two are given
def _get_bootable_partition_args(mbr_image, efi_boot_image):
    partition_args = []
    if mbr_image:
        partition_args += [
            "--grub2-mbr", mbr_image,
            "--protective-msdos-label",
            "-partition_cyl_align", "off",
            "-partition_offset", "16",
            "--mbr-force-bootable",
        ]
    if efi_boot_image:
        partition_args += [
            "-append_partition", "2", EFI_PARTITION_TYPE, efi_boot_image,
            "-appended_part_as_gpt",
            "-iso_mbr_part_type", ISO_MBR_PARTITION_TYPE,
        ]
    return partition_args

# El torito catalogue arguments for the bios boot image and the appended efi partition, for
# whichever of the two are given
def _get_bootable_eltorito_args(bios_boot_image, efi_boot_image):
    eltorito_args = []
    if bios_boot_image:
        eltorito_args += [
            "-b", bios_boot_image,
            "-c", "boot.catalog",
            "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
            "--grub2-boot-info",
        ]
    if efi_boot_image:

        # The catalogue entry points at the appended partition rather than at
        # a file, so the same bytes serve both ways of booting.
        eltorito_args += [
            "-eltorito-alt-boot",
            "-e", "--interval:appended_partition_2:all::",
            "-no-emul-boot",
        ]
    return eltorito_args

# Build the command that packs a tree as an iso that boots from a disc and, with
# the efi image appended as a real partition and the boot code in the system
# area, from a usb stick
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
    create_cmd += _get_bootable_partition_args(mbr_image, efi_boot_image)
    create_cmd += _get_bootable_eltorito_args(bios_boot_image, efi_boot_image)
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
        options = commandbase.create_command_options(
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

# Where the iso is mounted: its drive root from PowerShell on Windows (None when not mounted), otherwise mount_dir
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
            options = commandbase.create_command_options(
                is_shell=True),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

        # Get drive letter
        drive_text = drive_output
        if isinstance(drive_output, bytes):
            drive_text = drive_output.decode()
        drive_text = (drive_text or "").strip()
        if drive_text:
            return f"{drive_text}:\\"
        return None

    # Mount point matches expectations
    return mount_dir

# Mount an iso with PowerShell's Mount-DiskImage; True when it exits cleanly
def _mount_iso_windows(iso_file, verbose, pretend_run, exit_on_failure):

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
    return code == 0

# Mount an iso on mount_dir with fuseiso; False when fuseiso is missing or fails
def _mount_iso_linux(iso_file, mount_dir, verbose, pretend_run, exit_on_failure):

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
    return code == 0

# Mount an iso with Mount-DiskImage on Windows or fuseiso on Linux, unless it is already mounted; True when the mount holds files
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
        if not _mount_iso_windows(iso_file, verbose, pretend_run, exit_on_failure):
            return False

    # Linux
    elif platform_info.is_linux_platform():
        if not _mount_iso_linux(iso_file, mount_dir, verbose, pretend_run, exit_on_failure):
            return False

    # Check result
    return is_iso_mounted(iso_file, mount_dir)

# Unmount an iso with PowerShell's Dismount-DiskImage; True when it exits cleanly
def _unmount_iso_windows(iso_file, verbose, pretend_run, exit_on_failure):

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
    return code == 0

# Unmount mount_dir with fusermount -u; False when fusermount is missing or fails
def _unmount_iso_linux(mount_dir, verbose, pretend_run, exit_on_failure):

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
        options = commandbase.create_command_options(
            blocking_processes = [iso_tool]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    return code == 0

# Unmount an iso with Dismount-DiskImage or fusermount -u and remove the mount folder; True when it is no longer mounted
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
        if not _unmount_iso_windows(iso_file, verbose, pretend_run, exit_on_failure):
            return False

    # Linux
    elif platform_info.is_linux_platform():
        if not _unmount_iso_linux(mount_dir, verbose, pretend_run, exit_on_failure):
            return False

    # Remove mount point
    fileops.remove_directory(
        src = mount_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

    # Check result
    return not is_iso_mounted(iso_file, mount_dir)

###########################################################
# Batch extraction and creation
###########################################################

# Extract one disc image: the Mac side for HFS, otherwise as an ISO or as a 7-Zip archive
def _extract_disc_image(image_file, output_dir, filesystem, extract_method, skip_existing = False, delete_original = False, verbose = False, pretend_run = False, exit_on_failure = False):
    if filesystem == config.DiscFilesystemType.HFS:
        hfs.extract_hfs(
            image_file = image_file,
            extract_dir = output_dir,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    elif extract_method == config.DiscExtractType.ISO:
        extract_iso(
            iso_file = image_file,
            extract_dir = output_dir,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        archive.extract_archive(
            archive_file = image_file,
            extract_dir = output_dir,
            skip_existing = skip_existing,
            delete_original = delete_original,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Extract each ISO and Toast image under the input path into a folder beside it, skipping
# images whose folder already exists
def extract_disc_images(input_path, filesystem, extract_method, skip_existing = False, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    disc_image_extensions = [config.DiscImageFileType.ISO.cval(), config.DiscImageFileType.TOAST.cval()]
    for file in paths.build_file_list_by_extensions(input_path, extensions = disc_image_extensions):
        current_dir = paths.get_filename_directory(file)
        current_basename = paths.get_filename_basename(file)
        output_dir = paths.join_paths(current_dir, current_basename)
        if paths.is_path_directory(output_dir):
            continue
        _extract_disc_image(
            file, output_dir, filesystem, extract_method,
            skip_existing = skip_existing,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Build an ISO from each top-level folder in the input directory, skipping existing ISOs; each
# image takes its folder's name as its volume name when auto_volume_name is set
def create_isos_from_folders(input_path, volume_name = "", auto_volume_name = False, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for obj in paths.get_directory_contents(input_path):
        obj_path = paths.join_paths(input_path, obj)
        if not paths.is_path_directory(obj_path):
            continue
        output_file = paths.join_paths(input_path, obj + config.DiscImageFileType.ISO.cval())
        if paths.does_path_exist(output_file):
            continue
        create_iso(
            iso_file = output_file,
            source_dir = obj_path,
            volume_name = obj if auto_volume_name else volume_name,
            delete_original = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Extract one zip beside itself and build an ISO from its contents
def _create_iso_from_zip(zip_file, output_file, volume_name, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    current_dir = paths.get_filename_directory(zip_file)
    current_basename = paths.get_filename_basename(zip_file)
    extracted_dir = paths.join_paths(current_dir, current_basename + "_extracted")
    archive.extract_archive(
        archive_file = zip_file,
        extract_dir = extracted_dir,
        delete_original = delete_originals,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    create_iso(
        iso_file = output_file,
        source_dir = extracted_dir,
        volume_name = volume_name,
        delete_original = delete_originals,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Build an ISO from the contents of each zip under the input directory, skipping existing ISOs;
# each image takes its zip's name as its volume name when auto_volume_name is set
def create_isos_from_zips(input_path, volume_name = "", auto_volume_name = False, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    for file in paths.build_file_list_by_extensions(input_path, extensions = [".zip"]):
        current_dir = paths.get_filename_directory(file)
        current_basename = paths.get_filename_basename(file)
        output_file = paths.join_paths(current_dir, current_basename + config.DiscImageFileType.ISO.cval())
        if paths.does_path_exist(output_file):
            continue
        _create_iso_from_zip(
            file, output_file,
            current_basename if auto_volume_name else volume_name,
            delete_originals = delete_originals,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

# Build an ISO from each folder in the input directory, or from each zip under it
def create_isos(input_path, disc_source_type, volume_name = "", auto_volume_name = False, delete_originals = False, verbose = False, pretend_run = False, exit_on_failure = False):
    create_function = create_isos_from_folders
    if disc_source_type != config.DiscSourceType.FOLDER:
        create_function = create_isos_from_zips
    create_function(
        input_path,
        volume_name = volume_name,
        auto_volume_name = auto_volume_name,
        delete_originals = delete_originals,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
