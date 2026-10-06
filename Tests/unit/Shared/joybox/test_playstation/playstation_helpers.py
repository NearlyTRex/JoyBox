# Imports
import os

CONTENT_ID = "UP0001-TEST00000_00-0000000000000000"

# A disc key's shape, 32 hex digits, and plainly not a real one
FAKE_DISC_KEY = "0" * 32

TOOL_PATHS = {
    "PS3Dec": "/tools/ps3dec",
    "PSVStrip": "/tools/psvstrip",
    "PSVTools": "/tools/psvtools.py",
    "PSNGetPkgInfo": "/tools/psngetpkginfo.py",
    "PythonVenvPython": "/tools/venv/python",
}


def write_at(path, offset, value = CONTENT_ID, size = 0x24):
    payload = bytearray(os.urandom(offset + size + 64))
    payload[offset:offset + size] = value.encode("utf-8").ljust(size, b"\x00")
    with open(str(path), "wb") as handle:
        handle.write(bytes(payload))
    return str(path)
