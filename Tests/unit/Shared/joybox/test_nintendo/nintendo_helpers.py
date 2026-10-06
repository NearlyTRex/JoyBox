TOOL_PATHS = {
    "NDecrypt": "/tools/ndecrypt",
    "CtrMakeRom": "/tools/makerom",
    "CtrTool": "/tools/ctrtool",
    "3DSRomTool": "/tools/3dsromtool",
    "CDecrypt": "/tools/cdecrypt",
    "HacTool": "/tools/hactool",
    "XCITrimmer": "/tools/xcitrimmer.py",
    "PythonVenvPython": "/tools/venv/python",
}

VALID_ID = "F6F389D41D6BC0BDD6BD928C526AE556"


def read_dat(path):
    with open(str(path), "rb") as handle:
        return handle.read()
