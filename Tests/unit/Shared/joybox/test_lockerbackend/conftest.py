# Imports
import os
import sys

# Third-party imports
import pytest

# Local imports
from joybox import lockerbackend

# Helpers beside this file are imported by name, so this directory has to be
# importable; pytest only loads conftest itself. Appended rather than inserted:
# in front, this directory's own conftest would shadow the suite's top level
# one for everything that imports it by name.
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.append(_here)


@pytest.fixture
def remote(monkeypatch):
    # Records what would have been asked of rclone.
    state = {"calls": [], "result": True, "exists": True, "contains": True,
             "listing": {"Game.zip": {"hash": "aaaa"}}, "results": {}}

    def record(name, result_key = "result"):
        def run(*args, **kwargs):
            # The file list is a temporary file the caller deletes afterwards,
            # so its contents are read while the call is still in progress.
            if kwargs.get("files_from") and os.path.isfile(kwargs["files_from"]):
                with open(kwargs["files_from"]) as handle:
                    kwargs = dict(kwargs, files_listed = handle.read().strip())
            state["calls"].append({"name": name, "args": args, "kwargs": kwargs})
            if name in state["results"]:
                return state["results"][name]
            return state[result_key]
        return run

    for name, key in [
        ("upload_files_to_remote", "result"),
        ("download_files_from_remote", "result"),
        ("copy_remote_to_remote", "result"),
        ("recycle_files_on_remote", "result"),
        ("clear_hash_sidecar_files", "result"),
        ("upload_hash_sidecar_files", "result"),
        ("list_files_with_hashes", "listing"),
        ("list_files_with_hashes_from_sidecar", "listing"),
        ("does_path_exist", "exists"),
        ("does_file_exist", "exists"),
        ("does_path_contain_files", "contains"),
    ]:
        monkeypatch.setattr(lockerbackend.sync, name, record(name, key))
    return state


@pytest.fixture
def cryption(monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    state = {"encrypted": [], "decrypted": [], "result": True, "scratch": str(scratch),
             "removed": []}

    monkeypatch.setattr(
        lockerbackend.fileops, "create_temporary_directory",
        lambda **kwargs: (True, str(scratch)))
    monkeypatch.setattr(
        lockerbackend.fileops, "remove_directory",
        lambda src, **kwargs: state["removed"].append(src))
    monkeypatch.setattr(
        lockerbackend.cryption, "generate_encrypted_filename", lambda name: name + ".enc")

    def encrypt_file(src, passphrase, output_file, **kwargs):
        state["encrypted"].append({"src": src, "out": output_file})
        return state["result"]

    def decrypt_file(src, passphrase, output_file, **kwargs):
        state["decrypted"].append({"src": src, "out": output_file})
        return state["result"]

    monkeypatch.setattr(lockerbackend.cryption, "encrypt_file", encrypt_file)
    monkeypatch.setattr(lockerbackend.cryption, "decrypt_file", decrypt_file)
    return state
