# Imports
import struct

# Local imports
from joybox import mds


###########################################################
# Descriptor builder
#
# Lays out a version 1 descriptor the way Alcohol writes one: header, one
# session block, lead-in blocks then track blocks, an extra block per track and
# a footer naming the data file.
###########################################################

def build_mds(tracks, medium = 0x00, sessions = 1, version = (1, 5), filename = "*.mdf",
              widechar = False, lead_in = True, signature = b"MEDIA DESCRIPTOR"):
    lead_in_points = [0xA0, 0xA1, 0xA2] if lead_in else []
    num_blocks = len(lead_in_points) + len(tracks)
    session_offset = 88
    tracks_offset = session_offset + 24
    extras_offset = tracks_offset + num_blocks * 80
    footer_offset = extras_offset + len(tracks) * 8
    filename_offset = footer_offset + 16

    header = bytearray(88)
    header[0:16] = signature
    header[16:18] = bytes(version)
    struct.pack_into("<HH", header, 0x12, medium, sessions)
    struct.pack_into("<I", header, 0x50, session_offset)
    session = struct.pack("<iiHBBHHII", -150, 0, 1, num_blocks, len(lead_in_points), 1, len(tracks), 0, tracks_offset)

    blocks = b""
    for point in lead_in_points:
        blocks += mds.mds_track_block.pack(*([0, 0, 0x14, 0, point] + [0] * 7), 0, 0, 0, 0, 0, 0)
    extras = b""
    for index, track in enumerate(tracks):
        blocks += mds.mds_track_block.pack(
            track.get("mode", 0xAA), track.get("subchannel", 0), 0x14, 0, track.get("point", index + 1),
            0, 0, 0, 0, 0, 0, 0,
            0 if medium in mds.mds_dvd_media or track.get("no_extra") else extras_offset + index * 8,
            track.get("sector_size", 2048), 0, track.get("start_offset", 0), track.get("files", 1), footer_offset)
        extras += struct.pack("<II", track.get("pregap", 150 if index == 0 else 0), track.get("length", 0))

    footer = struct.pack("<IIII", filename_offset, 1 if widechar else 0, 0, 0)
    name = filename.encode("utf-16-le") + b"\0\0" if widechar else filename.encode("cp1252") + b"\0"
    return bytes(header) + session + blocks + extras + footer + name
