# Local imports
from joybox import config, lockerbackend


###########################################################
# Shared values for the locker backend suite
###########################################################

REMOTE_NAME = "hetzner"
REMOTE_PATH = "/Locker"


class FakeLockerInfo:

    def __init__(self, encrypted = False, remote_path = REMOTE_PATH, passphrase = None):
        self.encrypted = encrypted
        self.remote_path = remote_path
        self.passphrase = passphrase

    def get_name(self):
        return REMOTE_NAME

    def get_type(self):
        return config.RemoteType.SFTP

    def get_remote_path(self):
        return self.remote_path

    def get_mount_path(self):
        return None

    def is_encrypted(self):
        return self.encrypted

    def is_local_only(self):
        return False

    def get_passphrase(self):
        return self.passphrase


class FakeLocalBackend(lockerbackend.LocalBackend):

    def __init__(self, root):
        self.root_path = root
        self.locker_info = None


def only(state, name):
    matching = [call for call in state["calls"] if call["name"] == name]
    assert len(matching) == 1, "expected one %s call, recorded %d" % (name, len(matching))
    return matching[0]["kwargs"]


def called(state, name):
    return [call["kwargs"] for call in state["calls"] if call["name"] == name]


def backend(**kwargs):
    return lockerbackend.RemoteBackend(FakeLockerInfo(**kwargs))


def make_locker(tmp_path, files):
    root = tmp_path / "locker"
    root.mkdir(exist_ok = True)
    for rel, content in files.items():
        target = root / rel
        target.parent.mkdir(parents = True, exist_ok = True)
        target.write_text(content)
    return FakeLocalBackend(str(root))
