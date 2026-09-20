# Third-party imports
import pytest

# Local imports
from joybox import sync
from sync_helpers import REMOTE, REMOTE_TYPE, positional_arguments, record


###########################################################
# Moving, deleting and purging
###########################################################

def test_a_move_names_both_remote_paths(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.move_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Old", "/Gaming/New")
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "move"
    assert arguments[1].endswith("/Gaming/Old")
    assert arguments[2].endswith("/Gaming/New")


def test_a_move_keeps_source_and_destination_apart(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.move_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Old", "/Gaming/New")
    arguments = positional_arguments(recorder.only())

    assert arguments[1] != arguments[2]


def test_a_purge_removes_a_whole_path(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.purge_path_on_remote(REMOTE, REMOTE_TYPE, "/Gaming/Old")
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "purge"
    assert arguments[1].endswith("/Gaming/Old")


def test_a_purge_names_exactly_one_path(rclone, monkeypatch):
    # A second path would be purged too.
    recorder = record(monkeypatch)
    sync.purge_path_on_remote(REMOTE, REMOTE_TYPE, "/Gaming/Old")

    assert len(positional_arguments(recorder.only())) == 2


def test_a_delete_removes_one_file(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.delete_file_on_remote(REMOTE, REMOTE_TYPE, "/Gaming/game.zip")
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "deletefile"
    assert arguments[1].endswith("/Gaming/game.zip")


def test_a_delete_does_not_purge(rclone, monkeypatch):
    # deletefile refuses a directory; purge would take the whole tree.
    recorder = record(monkeypatch)
    sync.delete_file_on_remote(REMOTE, REMOTE_TYPE, "/Gaming/game.zip")

    assert "purge" not in recorder.only()


def test_a_directory_is_created(rclone, monkeypatch):
    recorder = record(monkeypatch)
    sync.create_remote_directory(REMOTE, REMOTE_TYPE, "/Gaming/New")
    arguments = positional_arguments(recorder.only())

    assert arguments[0] == "mkdir"
    assert arguments[1].endswith("/Gaming/New")


@pytest.mark.parametrize("call", [
    "purge_path_on_remote", "delete_file_on_remote", "create_remote_directory"])
def test_a_failed_destructive_command_is_reported(rclone, monkeypatch, call):
    record(monkeypatch, returncode = 1)

    assert getattr(sync, call)(REMOTE, REMOTE_TYPE, "/Gaming/x") is False


@pytest.mark.parametrize("call", [
    "purge_path_on_remote", "delete_file_on_remote", "create_remote_directory"])
def test_a_destructive_command_without_rclone_is_refused(
        no_rclone, recording_command, call):
    assert getattr(sync, call)(REMOTE, REMOTE_TYPE, "/Gaming/x") is False
    assert recording_command.ran() is False


###########################################################
# Recycling
#
# The reversible form of a remote delete.
###########################################################

@pytest.fixture
def recorded_move(monkeypatch):
    moved = []
    monkeypatch.setattr(
        sync, "move_files_on_remote",
        lambda **kwargs: moved.append(kwargs) or True)
    return moved


@pytest.fixture
def file_list(tmp_path):
    listing = tmp_path / "recycle.txt"
    listing.write_text("game.zip\nother.zip\n")
    return str(listing)


def test_recycling_needs_a_file_list():
    # Without one rclone move would take the whole path into the bin.
    import inspect

    signature = inspect.signature(sync.recycle_files_on_remote)
    assert signature.parameters["files_from"].default is inspect.Parameter.empty


def test_recycling_moves_into_the_bin(rclone, recorded_move, file_list):
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list)

    assert recorded_move[0]["src_path"] == "/Gaming/Roms"
    assert recorded_move[0]["dest_path"] == "/Gaming/Roms/.recycle_bin"


def test_recycling_passes_its_file_list_on(rclone, recorded_move, file_list):
    # This is what keeps the move to the named files.
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list)

    assert recorded_move[0]["files_from"] == file_list


def test_recycling_never_purges(rclone, monkeypatch, file_list):
    # The whole point is that it stays recoverable.
    monkeypatch.setattr(sync, "move_files_on_remote", lambda **kwargs: True)

    def fail(**kwargs):
        raise AssertionError("recycling must not purge")

    monkeypatch.setattr(sync, "purge_path_on_remote", fail)
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list)


def test_a_custom_recycle_folder_is_used(rclone, recorded_move, file_list):
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list, recycle_folder = ".trash")

    assert recorded_move[0]["dest_path"] == "/Gaming/Roms/.trash"


def test_a_recycle_path_uses_forward_slashes(rclone, recorded_move, file_list):
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list)

    assert "\\" not in recorded_move[0]["dest_path"]


def test_the_bin_is_inside_the_path_being_recycled(rclone, recorded_move, file_list):
    sync.recycle_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Roms", file_list)

    assert recorded_move[0]["dest_path"].startswith(recorded_move[0]["src_path"])


def test_a_move_without_a_file_list_omits_the_flag(rclone, monkeypatch, tmp_path):
    # rclone then moves everything under the source, which is why recycling
    # requires the list.
    recorder = record(monkeypatch)
    sync.move_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Old", "/Gaming/New",
        files_from = str(tmp_path / "absent.txt"))

    assert "--files-from" not in recorder.only()


def test_a_move_with_a_file_list_passes_it(rclone, monkeypatch, file_list):
    recorder = record(monkeypatch)
    sync.move_files_on_remote(
        REMOTE, REMOTE_TYPE, "/Gaming/Old", "/Gaming/New", files_from = file_list)

    assert recorder.value_after("--files-from") == file_list


def test_emptying_the_bin_purges_only_the_bin(rclone, monkeypatch):
    purged = []
    monkeypatch.setattr(
        sync, "purge_path_on_remote",
        lambda **kwargs: purged.append(kwargs) or True)
    sync.empty_recycle_bin(REMOTE, REMOTE_TYPE, "/Gaming/Roms")

    assert purged[0]["remote_path"] == "/Gaming/Roms/.recycle_bin"


def test_emptying_the_bin_never_purges_its_parent(rclone, monkeypatch):
    # Purging the parent would take the library with it.
    purged = []
    monkeypatch.setattr(
        sync, "purge_path_on_remote",
        lambda **kwargs: purged.append(kwargs) or True)
    sync.empty_recycle_bin(REMOTE, REMOTE_TYPE, "/Gaming/Roms")

    assert purged[0]["remote_path"] != "/Gaming/Roms"


