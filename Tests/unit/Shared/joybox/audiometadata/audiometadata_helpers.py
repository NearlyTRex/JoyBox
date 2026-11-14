# Imports
import base64
import struct

# A silent MPEG-1 Layer III frame, repeated enough for mutagen to parse it as
# audio. Built here rather than fetched so the tests need no external tool.
MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 413

# A one pixel PNG, for the artwork frames
PNG_PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


def box(kind, payload = b""):
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def full_box(kind, payload):
    return box(kind, b"\0\0\0\0" + payload)


# The smallest MP4 container mutagen accepts: a sound track with no samples.
# Tags live in moov, so this is all the tag code ever reads or writes.
def build_m4a():
    mdhd = full_box(b"mdhd", struct.pack(">IIIIHH", 0, 0, 44100, 44100, 0x55c4, 0))
    hdlr = full_box(b"hdlr", struct.pack(">I4s12s", 0, b"soun", b"\0" * 12) + b"\0")
    mdia = box(b"mdia", mdhd + hdlr + box(b"minf", box(b"stbl")))
    mvhd = full_box(b"mvhd", struct.pack(">IIII", 0, 0, 1000, 1000) + b"\0" * 80)
    moov = box(b"moov", mvhd + box(b"trak", mdia))
    return box(b"ftyp", b"M4A \0\0\0\0M4A isom") + moov + box(b"mdat")


def artwork(data = PNG_PIXEL, mime = "image/png", desc = "cover"):
    return {
        "data": base64.b64encode(data).decode("ascii"),
        "mime": mime,
        "type": 3,
        "desc": desc,
    }
