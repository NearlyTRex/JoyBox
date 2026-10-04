# Local imports
from joybox import computer


TOKEN_MAP = {
    "$GAME_INSTALL_DIR": "/prefix/drive_c/Game",
    "$GAME_SAVE_DIR": "/prefix/saves",
}


def program(**values):
    entry = computer.Program()
    for key, value in values.items():
        getattr(entry, "set_" + key)(value)
    return entry


PLAIN_ACCESSORS = [
    ("env", "get_env", {"LANG": "C"}),
    ("args", "get_args", ["-windowed"]),
    ("winver", "get_winver", "win7"),
    ("tricks", "get_tricks", ["d3dx9"]),
    ("overrides", "get_overrides", ["ddraw=n,b"]),
    ("desktop", "get_desktop", "1024x768"),
    ("installer_type", "get_installer_type", "inno"),
    ("serial", "get_serial", "AAAA-BBBB"),
]


def step(**values):
    entry = computer.ProgramStep()
    for key, value in values.items():
        getattr(entry, "set_" + key)(value)
    return entry


# Stands in for CommandOptions in run(); copy() returns itself so the test
# sees what run() set on its copy.
class FakeOptions:

    def __init__(self):
        self.blocking = []
        self.forced = False
        self.mapped = False
        self.cwd = None

    def copy(self):
        return self

    def set_blocking_processes(self, value):
        self.blocking = value

    def add_blocking_processes(self, value):
        self.blocking += value

    def set_force_prefix(self, value):
        self.forced = value

    def set_is_prefix_mapped_cwd(self, value):
        self.mapped = value

    def set_cwd(self, value):
        self.cwd = value

    def get_prefix_dos_c_drive(self):
        return "/prefix/dos"

    def get_prefix_c_drive_real(self):
        return "/prefix/drive_c"
