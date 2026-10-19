# Imports
import struct

# Third-party imports
import machfs

# Local imports
from joybox import hfs


###########################################################
# Disc images for the HFS tests
#
# Classic HFS volumes are written with machfs. HFS+ volumes are laid out here
# byte by byte from Apple's TN1150: a volume header, an extents overflow
# B-tree and a catalog B-tree, each in blocks of a small volume. Either can be
# wrapped in an Apple partition map, as Toast lays it out on hybrid discs.
###########################################################

CLASSIC_VOLUME_SIZE = 400 * 1024
HFS_START_BLOCK = 64

BLOCK_SIZE = 512
NODE_SIZE = 512
FIRST_DATA_BLOCK = 4

# 2005-01-01 00:00:00 in HFS time
NEW_YEAR_2005 = 1104537600 + hfs.hfs_to_unix_seconds

APPLICATION_INFO = b"APPLPJ03" + b"\0" * 24
HARD_LINK_INFO = hfs.hfsplus_hard_link_finder_info + b"\0" * 24


def make_file(data = b"", rsrc = b"", file_type = b"    ", creator = b"    ", flags = 0, mddate = 0):
    hfs_file = machfs.File()
    hfs_file.data = data
    hfs_file.rsrc = rsrc
    hfs_file.type = file_type
    hfs_file.creator = creator
    hfs_file.flags = flags
    hfs_file.crdate = hfs_file.mddate = mddate
    return hfs_file


def make_classic_volume():
    volume = machfs.Volume()
    volume.name = "Hybrid"
    volume["Read Me"] = make_file(data = b"plain text", mddate = NEW_YEAR_2005)
    volume["Start"] = make_file(data = b"code", rsrc = b"resources", file_type = b"APPL", creator = b"PJ03")
    folder = machfs.Folder()
    folder["Either/Or"] = make_file(data = b"slashed")
    volume["Extras"] = folder
    return volume.write(CLASSIC_VOLUME_SIZE)


def make_partition_entry(entry_count, start_block, block_count, partition_type):
    entry = b"PM" + b"\0\0" + struct.pack(">III", entry_count, start_block, block_count)
    entry += b"Partition".ljust(32, b"\0") + partition_type.ljust(32, b"\0")
    return entry.ljust(512, b"\0")


def make_apm_image(volume, partition_type = b"Apple_HFS", block_size = 512):
    image = b"ER" + struct.pack(">H", block_size)
    image = image.ljust(512, b"\0")
    image += make_partition_entry(2, 1, 2, b"Apple_partition_map")
    image += make_partition_entry(2, HFS_START_BLOCK, len(volume) // 512, partition_type)
    return image.ljust(HFS_START_BLOCK * 512, b"\0") + volume


def make_signed_image(signature, embedded_signature = b"\0\0", size = 4096):
    image = bytearray(size)
    image[1024:1026] = signature
    image[1024 + 0x7C:1024 + 0x7E] = embedded_signature
    return bytes(image)


def make_wrapped_image(volume, embed_start = 8):
    # An HFS wrapper whose embedded extent holds the HFS+ volume, in 512-byte allocation blocks
    wrapper = bytearray(make_signed_image(b"BD", embedded_signature = b"H+", size = embed_start * 512))
    wrapper[1024 + 0x14:1024 + 0x18] = struct.pack(">I", 512)
    wrapper[1024 + 0x7E:1024 + 0x82] = struct.pack(">HH", embed_start, len(volume) // 512)
    return bytes(wrapper) + volume


def read_appledouble_entries(blob):
    magic, version, _, count = struct.unpack(">II16sH", blob[:26])
    entries = {}
    for index in range(count):
        entry_id, offset, length = struct.unpack(">III", blob[26 + 12 * index:38 + 12 * index])
        entries[entry_id] = blob[offset:offset + length]
    return magic, version, entries


###########################################################
# HFS+
###########################################################

def pack_fork_data(size, extents):
    blob = struct.pack(">QII", size, 0, sum(block_count for _, block_count in extents))
    for start_block, block_count in extents[:8]:
        blob += struct.pack(">II", start_block, block_count)
    return blob.ljust(80, b"\0")


def pack_leaf_node(records, forward_link):
    body = struct.pack(">IIbBHH", forward_link, 0, -1, 1, len(records), 0)
    offsets = []
    for record in records:
        offsets.append(len(body))
        body += record
    offsets.append(len(body))
    node = bytearray(body.ljust(NODE_SIZE, b"\0"))
    for index, offset in enumerate(offsets):
        node[NODE_SIZE - 2 * (index + 1):NODE_SIZE - 2 * index] = struct.pack(">H", offset)
    return bytes(node)


def build_btree(records, leaf_kind = -1, loop_last_leaf = False):
    leaves, current = [], []
    for record in records:
        if current and 14 + sum(len(item) for item in current + [record]) + 2 * (len(current) + 2) > NODE_SIZE:
            leaves.append(current)
            current = []
        current.append(record)
    if current:
        leaves.append(current)
    nodes = []
    for index, leaf in enumerate(leaves):
        forward_link = index + 2 if index + 1 < len(leaves) else (index + 1 if loop_last_leaf else 0)
        node = bytearray(pack_leaf_node(leaf, forward_link))
        node[8:9] = struct.pack(">b", leaf_kind)
        nodes.append(bytes(node))
    first_leaf = 1 if leaves else 0
    header = struct.pack(">IIbBHH", 0, 0, 1, 0, 3, 0)
    header += struct.pack(">HIIIIHHII", 1 if leaves else 0, first_leaf, len(records), first_leaf, len(leaves), NODE_SIZE, 516, len(nodes) + 1, 0)
    return header.ljust(NODE_SIZE, b"\0") + b"".join(nodes)


def catalog_record(parent_id, name, data):
    name_bytes = name.encode("utf-16-be")
    return struct.pack(">HIH", 6 + len(name_bytes), parent_id, len(name_bytes) // 2) + name_bytes + data


class HFSPlusBuilder:

    def __init__(self, signature = b"H+"):
        self.signature = signature
        self.blob = bytearray(FIRST_DATA_BLOCK * BLOCK_SIZE)
        self.catalog_records = []
        self.overflow_records = []
        self.add_folder(1, hfs.hfsplus_root_folder_id, "Volume")

    def allocate(self, data, fragments = 1):
        block_count = -(-len(data) // BLOCK_SIZE)
        if not block_count:
            return []
        extents = []
        fragment_size = -(-block_count // fragments)
        for first in range(0, block_count, fragment_size):
            count = min(fragment_size, block_count - first)
            start_block = len(self.blob) // BLOCK_SIZE + 1
            self.blob += bytes(BLOCK_SIZE)
            self.blob += data[first * BLOCK_SIZE:(first + count) * BLOCK_SIZE].ljust(count * BLOCK_SIZE, b"\0")
            extents.append((start_block, count))
        return extents

    def fork(self, file_id, fork_type, data, fragments = 1, keep_overflow = True, size = None):
        extents = self.allocate(data, fragments)
        for index in range(8, len(extents), 8):
            if keep_overflow:
                start_block = sum(block_count for _, block_count in extents[:index])
                record = struct.pack(">HBxII", 10, fork_type, file_id, start_block)
                record += b"".join(struct.pack(">II", *extent) for extent in extents[index:index + 8])
                self.overflow_records.append(record.ljust(76, b"\0"))
        return pack_fork_data(len(data) if size is None else size, extents)

    def add_folder(self, parent_id, folder_id, name, mddate = 0):
        data = struct.pack(">hHII", hfs.hfsplus_folder_record, 0, 0, folder_id)
        data += struct.pack(">IIIII", 0, mddate, 0, 0, 0) + bytes(56)
        self.catalog_records.append(catalog_record(parent_id, name, data))
        thread = struct.pack(">hHI", 3, 0, parent_id) + struct.pack(">H", len(name)) + name.encode("utf-16-be")
        self.catalog_records.append(catalog_record(folder_id, "", thread))

    def add_file(
        self,
        parent_id,
        file_id,
        name,
        data = b"",
        rsrc = b"",
        finder_info = bytes(32),
        mode = 0o100644,
        owner_flags = 0,
        special = 0,
        dates = (0, 0, 0),
        fragments = 1,
        keep_overflow = True,
        size = None):
        created, modified, backed_up = dates
        record = struct.pack(">hHII", hfs.hfsplus_file_record, 0, 0, file_id)
        record += struct.pack(">IIIII", created, modified, 0, 0, backed_up)
        record += struct.pack(">IIBBHI", 0, 0, 0, owner_flags, mode, special) + finder_info.ljust(32, b"\0") + bytes(8)
        record += self.fork(file_id, hfs.hfsplus_data_fork, data, fragments, keep_overflow, size)
        record += self.fork(file_id, hfs.hfsplus_resource_fork, rsrc)
        self.catalog_records.append(catalog_record(parent_id, name, record))

    def build(self, catalog_tree = None, catalog_fragments = 1):
        catalog_tree = catalog_tree if catalog_tree is not None else build_btree(sorted(self.catalog_records))
        catalog_fork = self.fork(hfs.hfsplus_catalog_file_id, hfs.hfsplus_data_fork, catalog_tree, catalog_fragments)
        extents_tree = build_btree(sorted(self.overflow_records))
        extents_fork = self.fork(hfs.hfsplus_extents_file_id, hfs.hfsplus_data_fork, extents_tree)
        header = bytearray(512)
        header[0:2] = self.signature
        header[hfs.hfsplus_block_size_offset:hfs.hfsplus_block_size_offset + 4] = struct.pack(">I", BLOCK_SIZE)
        header[hfs.hfsplus_extents_file_offset:hfs.hfsplus_extents_file_offset + 80] = extents_fork
        header[hfs.hfsplus_catalog_file_offset:hfs.hfsplus_catalog_file_offset + 80] = catalog_fork
        self.blob[1024:1536] = header
        self.blob += bytes(-len(self.blob) % 512)
        return bytes(self.blob)
