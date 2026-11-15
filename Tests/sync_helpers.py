# Imports
import os
import shutil

# Local imports
from joybox import config, sqlitedb, sync
from joybox import syncdiff, synclisting, syncremotes, synctransfers
from module_helpers import owner_of


###########################################################
# Shared values for the sync suites
#
# sync and the modules split from it are tested across several directories.
# Anything more than one file needs lives here, so a helper cannot drift
# between files or shadow another file's copy of itself.
###########################################################

REMOTE = "hetzner"
REMOTE_TYPE = config.RemoteType.members()[0]
LOCAL = "/locker/Gaming/Roms"
REMOTE_PATH = "/Gaming/Roms"
SYNC_MODULES = (sync, syncremotes, synctransfers, syncdiff, synclisting)


# The sync module that defines a function
def sync_owner(name):
    return owner_of(name, *SYNC_MODULES)


# The rclone path of REMOTE_PATH on REMOTE
def connection_path():
    return sync.get_remote_connection_path(REMOTE, REMOTE_TYPE, REMOTE_PATH)


# Everything up to the first flag: the subcommand and the paths it acts on
def positional_arguments(cmd):
    arguments = []
    for part in cmd[1:]:
        if str(part).startswith("-"):
            break
        arguments.append(part)
    return arguments


# Record what a wrapper would run instead of running it
def record(monkeypatch, returncode = 0, output = ""):
    from fakes import RecordingCommand

    return RecordingCommand(monkeypatch, returncode = returncode, output = output)


###########################################################
# Hash databases
###########################################################

def make_database(path, entries):
    database = sqlitedb.HashDatabase(str(path))
    database.open()
    database.initialize()
    database.set_hashes(entries)
    database.close()


def read_database(path):
    database = sqlitedb.HashDatabase(str(path))
    database.open()
    try:
        return {entry["file_path"]: entry for entry in database.get_all_hashes()}
    finally:
        database.close()


###########################################################
# A remote holding one hash database
#
# The sidecar is downloaded, edited and uploaded back. Standing a local file in
# for the remote copy lets the round trip be checked end to end.
###########################################################

class FakeRemote:

    def __init__(self, monkeypatch, store):
        self.store = store
        self.downloads = []
        self.uploads = []
        self.download_result = True
        self.upload_result = True
        monkeypatch.setattr(synctransfers, "download_files_from_remote", self.download)
        monkeypatch.setattr(synctransfers, "upload_files_to_remote", self.upload)
        monkeypatch.setattr(
            sync, "does_file_exist", lambda *args, **kwargs: os.path.exists(str(self.store)))

    def download(self, **kwargs):
        self.downloads.append(kwargs)
        if self.download_result and os.path.exists(str(self.store)) and not kwargs.get("pretend_run"):
            shutil.copyfile(str(self.store), kwargs["local_path"])
        return self.download_result

    def upload(self, **kwargs):
        self.uploads.append(kwargs)
        if self.upload_result and not kwargs.get("pretend_run"):
            shutil.copyfile(kwargs["local_path"], str(self.store))
        return self.upload_result
