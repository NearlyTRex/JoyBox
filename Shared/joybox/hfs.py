# Imports
import struct

# Local imports
import joybox.fileops as fileops
import joybox.logger as logger
import joybox.paths as paths
import joybox.serialization as serialization

# Volume signatures, 1024 bytes into the volume
hfs_signature = b"BD"
hfsplus_signatures = [b"H+", b"HX"]

# Apple partition map
apm_signature = b"ER"
apm_entry_signature = b"PM"
apm_hfs_partition_type = b"Apple_HFS"
apm_default_block_size = 512

# Seconds from the HFS epoch (1904) to the Unix epoch (1970) and to the AppleDouble epoch (2000)
hfs_to_unix_seconds = 2082844800
hfs_to_appledouble_seconds = 3029529600

# AppleDouble entries
appledouble_magic = 0x00051607
appledouble_version = 0x00020000
appledouble_entry_resource_fork = 2
appledouble_entry_file_dates = 8
appledouble_entry_finder_info = 9
appledouble_unknown_date = -0x80000000

# Find hfs volume
# Returns (offset, length, signature) of the HFS or HFS+ volume in a disc image, or None
def find_hfs_volume(image_file):
    header = serialization.read_binary_file(image_file, length = 1026)
    if not header or len(header) < 1026:
        return None

    # Volume behind an Apple partition map
    if header[0:2] == apm_signature:
        block_size = struct.unpack(">H", header[2:4])[0] or apm_default_block_size
        entry_count = 1
        index = 0
        while index < entry_count:
            entry = serialization.read_binary_file(image_file, offset = block_size * (index + 1), length = 80)
            if not entry or len(entry) < 80 or entry[0:2] != apm_entry_signature:
                return None
            entry_count, start_block, block_count = struct.unpack(">III", entry[4:16])
            if entry[48:80].rstrip(b"\0") == apm_hfs_partition_type:
                offset = start_block * block_size
                signature = serialization.read_binary_file(image_file, offset = offset + 1024, length = 2)
                return (offset, block_count * block_size, signature)
            index += 1
        return None

    # Bare volume, as on hybrids that lay ISO 9660 over an HFS volume without a partition map
    signature = header[1024:1026]
    if signature == hfs_signature or signature in hfsplus_signatures:
        return (0, paths.get_file_size(image_file), signature)
    return None

# Check if hfs volume wraps an hfs+ volume
def is_wrapped_hfsplus_volume(image_file, offset):
    embedded_signature = serialization.read_binary_file(image_file, offset = offset + 1024 + 0x7C, length = 2)
    return embedded_signature in hfsplus_signatures

# Get local filename
# HFS names may hold "/" but never ":", so they swap, as macOS does
def get_local_filename(hfs_name):
    local_name = hfs_name.replace("/", ":")
    if local_name in ["", ".", ".."]:
        return None
    return local_name

# Convert hfs date to appledouble date
def convert_hfs_date_to_appledouble(hfs_date):
    if not hfs_date:
        return appledouble_unknown_date
    return hfs_date - hfs_to_appledouble_seconds

# Check if hfs file needs appledouble
def does_hfs_file_need_appledouble(hfs_file):
    if len(hfs_file.rsrc):
        return True
    if hfs_file.flags:
        return True
    return hfs_file.type not in [b"\0\0\0\0", b"    "] or hfs_file.creator not in [b"\0\0\0\0", b"    "]

# Build appledouble
# Finder info, dates and resource fork, in the layout of a macOS ._ file
def build_appledouble(hfs_file):
    finder_info = struct.pack(">4s4sHHH", hfs_file.type, hfs_file.creator, hfs_file.flags, hfs_file.x, hfs_file.y).ljust(32, b"\0")
    file_dates = struct.pack(">iiii",
        convert_hfs_date_to_appledouble(hfs_file.crdate),
        convert_hfs_date_to_appledouble(hfs_file.mddate),
        convert_hfs_date_to_appledouble(hfs_file.bkdate),
        convert_hfs_date_to_appledouble(hfs_file.mddate))
    entries = [
        (appledouble_entry_file_dates, file_dates),
        (appledouble_entry_finder_info, finder_info),
        (appledouble_entry_resource_fork, bytes(hfs_file.rsrc))
    ]
    header = struct.pack(">II16sH", appledouble_magic, appledouble_version, b"", len(entries))
    offset = len(header) + 12 * len(entries)
    descriptors = b""
    for entry_id, entry_data in entries:
        descriptors += struct.pack(">III", entry_id, offset, len(entry_data))
        offset += len(entry_data)
    return header + descriptors + b"".join(entry_data for _, entry_data in entries)

# Extract hfs folder
def extract_hfs_folder(
    hfs_folder,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    import machfs

    # Make folder
    success = fileops.make_directory(
        src = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Extract each item
    for hfs_name, hfs_item in hfs_folder.items():
        local_name = get_local_filename(hfs_name)
        if not local_name:
            logger.log_warning("Skipping HFS item with unusable name '%s'" % hfs_name)
            continue
        local_path = paths.join_paths(extract_dir, local_name)

        # Extract subfolder
        if isinstance(hfs_item, machfs.Folder):
            success = extract_hfs_folder(
                hfs_folder = hfs_item,
                extract_dir = local_path,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False
            continue

        # Extract data fork
        success = fileops.touch_file(
            src = local_path,
            contents = bytes(hfs_item.data),
            contents_mode = "wb",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

        # Extract finder info and resource fork
        if does_hfs_file_need_appledouble(hfs_item):
            success = fileops.touch_file(
                src = paths.join_paths(extract_dir, "._" + local_name),
                contents = build_appledouble(hfs_item),
                contents_mode = "wb",
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
            if not success:
                return False

        # Keep modification date
        if hfs_item.mddate:
            fileops.set_file_modified_time(
                src = local_path,
                timestamp = hfs_item.mddate - hfs_to_unix_seconds,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
    return True

# Extract hfs
def extract_hfs(
    image_file,
    extract_dir,
    delete_original = False,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Check source
    if not paths.is_path_file(image_file):
        logger.log_error("Image file '%s' was not found" % image_file)
        return False

    # Find volume
    volume_info = find_hfs_volume(image_file)
    if not volume_info:
        logger.log_error("No HFS volume was found in '%s'" % image_file)
        return False
    volume_offset, volume_length, volume_signature = volume_info
    if volume_signature in hfsplus_signatures or is_wrapped_hfsplus_volume(image_file, volume_offset):
        logger.log_error("'%s' holds an HFS+ volume, which is not supported" % image_file)
        return False

    # Get tool
    try:
        import machfs
    except ImportError:
        logger.log_error("machfs was not found")
        return False

    # Read volume
    if verbose:
        logger.log_info("Reading HFS volume at offset %d of '%s'" % (volume_offset, image_file))
    volume_data = serialization.read_binary_file(
        image_file,
        offset = volume_offset,
        length = volume_length,
        exit_on_failure = exit_on_failure)
    if not volume_data:
        return False
    volume = machfs.Volume()
    try:
        volume.read(volume_data)
    except Exception as e:
        logger.log_error("Unable to read the HFS volume in '%s'" % image_file)
        logger.log_error(e)
        return False

    # Extract volume
    success = extract_hfs_folder(
        hfs_folder = volume,
        extract_dir = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Clean up
    if delete_original:
        fileops.remove_file(
            src = image_file,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Check result
    if pretend_run:
        return True
    return paths.does_directory_contain_files(extract_dir)
