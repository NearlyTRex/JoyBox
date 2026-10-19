# Imports
import stat
import struct
import unicodedata

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

# HFS+ volume header
hfsplus_block_size_offset = 40
hfsplus_extents_file_offset = 192
hfsplus_catalog_file_offset = 272

# HFS+ catalog
hfsplus_root_folder_id = 2
hfsplus_extents_file_id = 3
hfsplus_catalog_file_id = 4
hfsplus_folder_record = 1
hfsplus_file_record = 2
hfsplus_data_fork = 0x00
hfsplus_resource_fork = 0xFF
hfsplus_leaf_node = -1
hfsplus_hard_link_finder_info = b"hlnkhfs+"
hfsplus_compressed_flag = 0x20

# Filesystem internals at the root of an HFS+ volume
hfsplus_private_data_name = "\0\0\0\0HFS+ Private Data"
hfsplus_private_names = [hfsplus_private_data_name, ".HFS+ Private Directory Data\r", ".journal", ".journal_info_block"]

# Bytes read from the image at a time
hfsplus_chunk_size = 8 * 1024 * 1024

###########################################################
# Volumes
###########################################################

# Get hfs volume info
# An HFS volume that wraps an HFS+ volume gives the HFS+ volume inside it
def get_hfs_volume_info(image_file, offset, length):
    mdb = serialization.read_binary_file(image_file, offset = offset + 1024, length = 0x82)
    if not mdb or len(mdb) < 0x82:
        return None
    signature = mdb[0:2]
    if signature in hfsplus_signatures:
        return (offset, length, signature)
    if signature != hfs_signature:
        return None
    if mdb[0x7C:0x7E] in hfsplus_signatures:
        allocation_block_size = struct.unpack(">I", mdb[0x14:0x18])[0]
        allocation_start = struct.unpack(">H", mdb[0x1C:0x1E])[0]
        embed_start, embed_count = struct.unpack(">HH", mdb[0x7E:0x82])
        embedded_offset = offset + allocation_start * 512 + embed_start * allocation_block_size
        return (embedded_offset, embed_count * allocation_block_size, mdb[0x7C:0x7E])
    return (offset, length, signature)

# Find apm partition
# Returns (start_block, block_count) of the first partition of a type, reading entries spaced entry_size apart
def find_apm_partition(image_file, entry_size, partition_type):
    entry_count = 1
    index = 0
    while index < entry_count:
        entry = serialization.read_binary_file(image_file, offset = entry_size * (index + 1), length = 80)
        if not entry or len(entry) < 80 or entry[0:2] != apm_entry_signature:
            return None
        entry_count, start_block, block_count = struct.unpack(">III", entry[4:16])
        if entry[48:80].rstrip(b"\0") == partition_type:
            return (start_block, block_count)
        index += 1
    return None

# Find hfs volume
# Returns (offset, length, signature) of the HFS or HFS+ volume in a disc image, or None
def find_hfs_volume(image_file):
    header = serialization.read_binary_file(image_file, length = 4)
    if not header or len(header) < 4:
        return None

    # Volume behind an Apple partition map
    # CD maps often give 2048-byte blocks yet space their entries and count their partitions in 512 bytes
    if header[0:2] == apm_signature:
        block_size = struct.unpack(">H", header[2:4])[0] or apm_default_block_size
        for entry_size in sorted({apm_default_block_size, block_size}):
            partition = find_apm_partition(image_file, entry_size, apm_hfs_partition_type)
            if not partition:
                continue
            start_block, block_count = partition
            for unit_size in sorted({entry_size, block_size}):
                volume_info = get_hfs_volume_info(image_file, start_block * unit_size, block_count * unit_size)
                if volume_info:
                    return volume_info
        return None

    # Bare volume, as on hybrids that lay ISO 9660 over an HFS volume without a partition map
    return get_hfs_volume_info(image_file, 0, paths.get_file_size(image_file))

###########################################################
# Files
###########################################################

# Get local filename
# HFS names may hold "/" but never ":", so they swap, as macOS does
def get_local_filename(hfs_name):
    local_name = unicodedata.normalize("NFC", hfs_name).replace("/", ":")
    if local_name in ["", ".", ".."] or "\0" in local_name:
        return None
    return local_name

# Convert hfs date to appledouble date
def convert_hfs_date_to_appledouble(hfs_date):
    if not hfs_date:
        return appledouble_unknown_date
    return hfs_date - hfs_to_appledouble_seconds

# Check if finder info needs appledouble
def does_finder_info_need_appledouble(finder_info, resource_fork_size):
    if resource_fork_size:
        return True
    if struct.unpack(">H", finder_info[8:10])[0]:
        return True
    return finder_info[0:4] not in [b"\0\0\0\0", b"    "] or finder_info[4:8] not in [b"\0\0\0\0", b"    "]

# Build appledouble
# Finder info, dates and resource fork, in the layout of a macOS ._ file
def build_appledouble(finder_info, dates, resource_fork):
    created, modified, backed_up = dates
    file_dates = struct.pack(">iiii",
        convert_hfs_date_to_appledouble(created),
        convert_hfs_date_to_appledouble(modified),
        convert_hfs_date_to_appledouble(backed_up),
        convert_hfs_date_to_appledouble(modified))
    entries = [
        (appledouble_entry_file_dates, file_dates),
        (appledouble_entry_finder_info, finder_info.ljust(32, b"\0")[:32]),
        (appledouble_entry_resource_fork, bytes(resource_fork))
    ]
    header = struct.pack(">II16sH", appledouble_magic, appledouble_version, b"", len(entries))
    offset = len(header) + 12 * len(entries)
    descriptors = b""
    for entry_id, entry_data in entries:
        descriptors += struct.pack(">III", entry_id, offset, len(entry_data))
        offset += len(entry_data)
    return header + descriptors + b"".join(entry_data for _, entry_data in entries)

# Write mac metadata
# The AppleDouble file when there is anything for it to hold, then the modified date
def write_mac_metadata(
    local_path,
    finder_info,
    dates,
    resource_fork,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    if does_finder_info_need_appledouble(finder_info, len(resource_fork)):
        success = fileops.touch_file(
            src = paths.join_paths(paths.get_filename_directory(local_path), "._" + paths.get_filename_file(local_path)),
            contents = build_appledouble(finder_info, dates, resource_fork),
            contents_mode = "wb",
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    if dates[1]:
        fileops.set_file_modified_time(
            src = local_path,
            timestamp = dates[1] - hfs_to_unix_seconds,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    return True

###########################################################
# HFS
###########################################################

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

        # Extract finder info, dates and resource fork
        success = write_mac_metadata(
            local_path = local_path,
            finder_info = struct.pack(">4s4sHHH", hfs_item.type, hfs_item.creator, hfs_item.flags, hfs_item.x, hfs_item.y),
            dates = (hfs_item.crdate, hfs_item.mddate, hfs_item.bkdate),
            resource_fork = hfs_item.rsrc,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Extract hfs volume
def extract_hfs_volume(
    image_file,
    volume_offset,
    volume_length,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Get tool
    try:
        import machfs
    except ImportError:
        logger.log_error("machfs was not found")
        return False

    # Read volume
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
    return extract_hfs_folder(
        hfs_folder = volume,
        extract_dir = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

###########################################################
# HFS+
###########################################################

# Parse hfsplus fork data
def parse_hfsplus_fork_data(fork_data):
    logical_size, _, total_blocks = struct.unpack(">QII", fork_data[0:16])
    extents = [struct.unpack(">II", fork_data[16 + 8 * index:24 + 8 * index]) for index in range(8)]
    return {
        "size": logical_size,
        "blocks": total_blocks,
        "extents": [extent for extent in extents if extent[1]]
    }

# Get hfsplus fork extents
# The first eight live in the catalog; the rest in the extents overflow file, keyed by the fork block they start at
def get_hfsplus_fork_extents(volume, file_id, fork_type, fork):
    extents = list(fork["extents"])
    found_blocks = sum(block_count for _, block_count in extents)
    while found_blocks < fork["blocks"]:
        more_extents = volume["overflow"].get((file_id, fork_type, found_blocks))
        if not more_extents:
            break
        extents += more_extents
        found_blocks += sum(block_count for _, block_count in more_extents)
    return extents

# Iterate hfsplus fork
def iterate_hfsplus_fork(volume, file_id, fork_type, fork):
    remaining = fork["size"]
    for start_block, block_count in get_hfsplus_fork_extents(volume, file_id, fork_type, fork):
        position = volume["offset"] + start_block * volume["block_size"]
        extent_remaining = min(block_count * volume["block_size"], remaining)
        while extent_remaining > 0:
            length = min(hfsplus_chunk_size, extent_remaining)
            chunk = serialization.read_binary_file(volume["image_file"], offset = position, length = length)
            if not chunk or len(chunk) != length:
                raise ValueError("A fork of catalog node %d runs past the end of the image" % file_id)
            yield chunk
            position += length
            extent_remaining -= length
            remaining -= length
    if remaining > 0:
        raise ValueError("A fork of catalog node %d is missing %d bytes" % (file_id, remaining))

# Read hfsplus fork
def read_hfsplus_fork(volume, file_id, fork_type, fork):
    return b"".join(iterate_hfsplus_fork(volume, file_id, fork_type, fork))

# Iterate btree leaf records
def iterate_btree_leaf_records(tree_data):
    if len(tree_data) < 34:
        raise ValueError("A B-tree is too short for its header node")
    first_leaf_node = struct.unpack(">I", tree_data[24:28])[0]
    node_size = struct.unpack(">H", tree_data[32:34])[0]
    if not node_size:
        raise ValueError("A B-tree has no node size")
    node_index = first_leaf_node
    seen_nodes = set()
    while node_index and node_index not in seen_nodes:
        seen_nodes.add(node_index)
        node = tree_data[node_index * node_size:(node_index + 1) * node_size]
        if len(node) < node_size:
            raise ValueError("B-tree node %d is past the end of its file" % node_index)
        forward_link, _, node_kind, _, record_count = struct.unpack(">IIbBH", node[0:12])
        if node_kind != hfsplus_leaf_node:
            raise ValueError("B-tree node %d is not a leaf node" % node_index)
        offsets = [struct.unpack(">H", node[node_size - 2 * (index + 1):node_size - 2 * index])[0] for index in range(record_count + 1)]
        for index in range(record_count):
            yield node[offsets[index]:offsets[index + 1]]
        node_index = forward_link

# Parse hfsplus catalog record
def parse_hfsplus_catalog_record(record):
    key_length, parent_id, name_length = struct.unpack(">HIH", record[0:8])
    name = record[8:8 + 2 * name_length].decode("utf-16-be", errors = "replace")
    data = record[2 + key_length:]
    record_type = struct.unpack(">h", data[0:2])[0]
    if record_type not in [hfsplus_folder_record, hfsplus_file_record]:
        return None
    entry = {
        "folder": record_type == hfsplus_folder_record,
        "id": struct.unpack(">I", data[8:12])[0],
        "parent": parent_id,
        "name": name,
        "dates": struct.unpack(">III", data[12:20] + data[28:32]),
        "finder_info": data[48:80]
    }
    if record_type == hfsplus_file_record:
        entry["owner_flags"] = data[41]
        entry["mode"], entry["special"] = struct.unpack(">HI", data[42:48])
        entry["data_fork"] = parse_hfsplus_fork_data(data[88:168])
        entry["resource_fork"] = parse_hfsplus_fork_data(data[168:248])
    return entry

# Read hfsplus volume
def read_hfsplus_volume(image_file, volume_offset):
    header = serialization.read_binary_file(image_file, offset = volume_offset + 1024, length = 512)
    if not header or len(header) < 512:
        raise ValueError("The HFS+ volume header is past the end of the image")
    volume = {
        "image_file": image_file,
        "offset": volume_offset,
        "block_size": struct.unpack(">I", header[hfsplus_block_size_offset:hfsplus_block_size_offset + 4])[0],
        "overflow": {},
        "children": {}
    }

    # Read extents overflow file
    extents_fork = parse_hfsplus_fork_data(header[hfsplus_extents_file_offset:hfsplus_extents_file_offset + 80])
    extents_tree = read_hfsplus_fork(volume, hfsplus_extents_file_id, hfsplus_data_fork, extents_fork)
    for record in iterate_btree_leaf_records(extents_tree):
        fork_type, file_id, start_block = struct.unpack(">BxII", record[2:12])
        extents = [struct.unpack(">II", record[12 + 8 * index:20 + 8 * index]) for index in range(8)]
        volume["overflow"][(file_id, fork_type, start_block)] = [extent for extent in extents if extent[1]]

    # Read catalog file
    catalog_fork = parse_hfsplus_fork_data(header[hfsplus_catalog_file_offset:hfsplus_catalog_file_offset + 80])
    catalog_tree = read_hfsplus_fork(volume, hfsplus_catalog_file_id, hfsplus_data_fork, catalog_fork)
    for record in iterate_btree_leaf_records(catalog_tree):
        entry = parse_hfsplus_catalog_record(record)
        if entry:
            volume["children"].setdefault(entry["parent"], []).append(entry)
    return volume

# Get hfsplus hard link targets
# Hard-linked files keep their contents as iNode<number> files in a hidden folder at the root
def get_hfsplus_hard_link_targets(volume):
    for entry in volume["children"].get(hfsplus_root_folder_id, []):
        if entry["folder"] and entry["name"] == hfsplus_private_data_name:
            return {child["name"]: child for child in volume["children"].get(entry["id"], [])}
    return {}

# Extract hfsplus file
def extract_hfsplus_file(
    volume,
    entry,
    local_path,
    hard_link_targets,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Follow hard link
    source = entry
    if entry["finder_info"][0:8] == hfsplus_hard_link_finder_info:
        source = hard_link_targets.get("iNode%d" % entry["special"])
        if not source:
            logger.log_warning("Skipping hard link '%s' with no target" % local_path)
            return True

    # Skip compressed file
    if source["owner_flags"] & hfsplus_compressed_flag:
        logger.log_warning("Skipping compressed file '%s'" % local_path)
        return True

    # Make symlink
    if stat.S_ISLNK(source["mode"]):
        link_target = read_hfsplus_fork(volume, source["id"], hfsplus_data_fork, source["data_fork"])
        return fileops.create_symlink(
            src = link_target.decode("utf-8", errors = "replace"),
            dest = local_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Extract data fork
    contents_mode = "wb"
    for chunk in iterate_hfsplus_fork(volume, source["id"], hfsplus_data_fork, source["data_fork"]):
        success = fileops.touch_file(
            src = local_path,
            contents = chunk,
            contents_mode = contents_mode,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False
        contents_mode = "ab"
    if contents_mode == "wb":
        success = fileops.touch_file(
            src = local_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
        if not success:
            return False

    # Keep executable bit
    if source["mode"] & 0o111:
        fileops.mark_as_executable(
            src = local_path,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)

    # Extract finder info, dates and resource fork
    return write_mac_metadata(
        local_path = local_path,
        finder_info = source["finder_info"],
        dates = source["dates"],
        resource_fork = read_hfsplus_fork(volume, source["id"], hfsplus_resource_fork, source["resource_fork"]),
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)

# Extract hfsplus folder
def extract_hfsplus_folder(
    volume,
    folder_id,
    extract_dir,
    hard_link_targets,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):

    # Make folder
    success = fileops.make_directory(
        src = extract_dir,
        verbose = verbose,
        pretend_run = pretend_run,
        exit_on_failure = exit_on_failure)
    if not success:
        return False

    # Extract each item
    for entry in volume["children"].get(folder_id, []):
        if folder_id == hfsplus_root_folder_id and entry["name"] in hfsplus_private_names:
            continue
        local_name = get_local_filename(entry["name"])
        if not local_name:
            logger.log_warning("Skipping HFS+ item with unusable name '%s'" % entry["name"])
            continue
        local_path = paths.join_paths(extract_dir, local_name)
        if entry["folder"]:
            success = extract_hfsplus_folder(
                volume = volume,
                folder_id = entry["id"],
                extract_dir = local_path,
                hard_link_targets = hard_link_targets,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        else:
            success = extract_hfsplus_file(
                volume = volume,
                entry = entry,
                local_path = local_path,
                hard_link_targets = hard_link_targets,
                verbose = verbose,
                pretend_run = pretend_run,
                exit_on_failure = exit_on_failure)
        if not success:
            return False
    return True

# Extract hfsplus volume
def extract_hfsplus_volume(
    image_file,
    volume_offset,
    extract_dir,
    verbose = False,
    pretend_run = False,
    exit_on_failure = False):
    try:
        volume = read_hfsplus_volume(image_file, volume_offset)
        return extract_hfsplus_folder(
            volume = volume,
            folder_id = hfsplus_root_folder_id,
            extract_dir = extract_dir,
            hard_link_targets = get_hfsplus_hard_link_targets(volume),
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    except (ValueError, struct.error) as e:
        logger.log_error("Unable to read the HFS+ volume in '%s'" % image_file)
        logger.log_error(e)
        return False

###########################################################

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
    if verbose:
        logger.log_info("Reading %s volume at offset %d of '%s'" % (volume_signature.decode(), volume_offset, image_file))

    # Extract volume
    if volume_signature in hfsplus_signatures:
        success = extract_hfsplus_volume(
            image_file = image_file,
            volume_offset = volume_offset,
            extract_dir = extract_dir,
            verbose = verbose,
            pretend_run = pretend_run,
            exit_on_failure = exit_on_failure)
    else:
        success = extract_hfs_volume(
            image_file = image_file,
            volume_offset = volume_offset,
            volume_length = volume_length,
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
