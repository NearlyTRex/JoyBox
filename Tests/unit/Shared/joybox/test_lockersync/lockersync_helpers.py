# Local imports
from joybox import config, lockerbackend


###########################################################
# Shared values for the locker sync suite
###########################################################

def entry(hash_value = "aaaa", size = 1024):
    return {"hash": hash_value, "size": size, "mtime": 1700000000}


def transfer_action(action_type = None, src = "Game.zip"):
    return {
        "type": action_type or config.SyncActionType.COPY,
        "src": src,
        "dest": src,
        "src_data": entry(),
    }


def orphan_action(path = "Old.zip"):
    return {"type": config.SyncActionType.RECYCLE, "path": path, "src_data": entry()}


###########################################################
# A backend that records what it is asked to do
###########################################################

class FakeBackend:

    def __init__(self, result = True, root = "/locker"):
        self.result = result
        self.root = root
        self.synced = []
        self.batched = []
        self.recycled = []

    def get_root_path(self):
        return self.root

    def sync_from(self, src_backend, src_rel_path, dest_rel_path, **kwargs):
        self.synced.append({
            "src": src_rel_path,
            "dest": dest_rel_path,
            "cryption": kwargs.get("cryption_type"),
            "passphrase": kwargs.get("passphrase"),
        })
        return self.result

    def sync_batch_from(self, src_backend, actions, cryption_type, **kwargs):
        self.batched.append({"actions": actions, "cryption": cryption_type, "kwargs": kwargs})
        paths = [action.get("dest", action.get("src", "")) for action in actions]
        if self.result:
            return (paths, [])
        return ([], paths)

    def recycle_file(self, rel_path, **kwargs):
        self.recycled.append(rel_path)
        return self.result


###########################################################
# Real backend types, so isinstance checks see a local or a remote locker
###########################################################

class RecordingMixin:

    def setup_recording(self, listing, sidecar, result):
        self.listing = listing
        self.sidecar = sidecar
        self.result = result
        self.sidecar_result = True
        self.listed = []
        self.sidecar_reads = []
        self.batched = []
        self.recycled = []
        self.sidecar_updates = []

    def list_files_with_hashes(self, **kwargs):
        self.listed.append(kwargs)
        return None if self.listing is None else dict(self.listing)

    def list_files_with_hashes_from_sidecar(self, **kwargs):
        self.sidecar_reads.append(kwargs)
        return None if self.sidecar is None else dict(self.sidecar)

    def sync_batch_from(self, src_backend, actions, cryption_type, **kwargs):
        self.batched.append({"actions": actions, "cryption": cryption_type, "kwargs": kwargs})
        paths = [action.get("dest", action.get("src", "")) for action in actions]
        if self.result:
            return (paths, [])
        return ([], paths)

    def recycle_file(self, rel_path, **kwargs):
        self.recycled.append(rel_path)
        return self.result

    def update_sidecar_from_local(self, **kwargs):
        self.sidecar_updates.append(kwargs)
        return self.sidecar_result


class FakeLocalLocker(RecordingMixin, lockerbackend.LocalBackend):

    def __init__(self, root, listing = None, result = True):
        self.locker_info = None
        self.root_path = root
        self.setup_recording({} if listing is None else listing, None, result)


class FakeRemoteLocker(RecordingMixin, lockerbackend.RemoteBackend):

    def __init__(self, remote_type = config.RemoteType.DRIVE, listing = None, sidecar = None, result = True):
        self.locker_info = None
        self.remote_name = "remote"
        self.remote_type = remote_type.val()
        self.remote_path = "/Locker"
        self.setup_recording({} if listing is None else listing, {} if sidecar is None else sidecar, result)


###########################################################
# Locker settings
###########################################################

class FakeLockerInfo:

    def __init__(self, name, encrypted = False, passphrase = None, excluded_dirs = None):
        self.name = name
        self.encrypted = encrypted
        self.passphrase = passphrase
        self.excluded_dirs = excluded_dirs or []

    def get_locker_name(self):
        return self.name

    def is_encrypted(self):
        return self.encrypted

    def get_passphrase(self):
        return self.passphrase

    def get_excluded_dirs(self):
        return list(self.excluded_dirs)
