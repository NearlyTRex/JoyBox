# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import fileops
from fileops_helpers import write, read, tree, make_source


###########################################################
# Bulk copy and move
###########################################################

BULK = [
    ("copy_contents", False),
    ("move_contents", True),
]

GLOBBED = [
    ("copy_globbed_files", False),
    ("move_globbed_files", True),
]


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_keeps_the_layout(tmp_path, function, moves):
    src = make_source(tmp_path / "src")
    dest = tmp_path / "dest"
    assert getattr(fileops, function)(src, str(dest), verbose = True)
    assert read(dest / "a.txt") == "a"
    assert read(dest / "sub" / "b.txt") == "b"
    assert os.path.exists(os.path.join(src, "a.txt")) is not moves


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_of_a_missing_source_exits_when_asked(tmp_path, function, moves):
    with pytest.raises(SystemExit):
        getattr(fileops, function)(str(tmp_path / "missing"), str(tmp_path / "dest"), exit_on_failure = True)


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_stops_at_a_failed_directory(tmp_path, monkeypatch, function, moves):
    src = make_source(tmp_path / "src")
    monkeypatch.setattr(fileops, "make_directory", lambda **kwargs: False)
    assert not getattr(fileops, function)(src, str(tmp_path / "dest"))


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_stops_at_a_failed_file(tmp_path, monkeypatch, function, moves):
    src = make_source(tmp_path / "src")
    monkeypatch.setattr(fileops, "transfer_file", lambda **kwargs: False)
    assert not getattr(fileops, function)(src, str(tmp_path / "dest"))


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_skips_failures_and_logs_them(tmp_path, monkeypatch, function, moves):
    src = make_source(tmp_path / "src")
    log = tmp_path / "errors.txt"
    real_transfer = fileops.transfer_file
    def flaky_transfer(**kwargs):
        if kwargs["src"].endswith("a.txt"):
            return False
        return real_transfer(**kwargs)
    monkeypatch.setattr(fileops, "transfer_file", flaky_transfer)
    assert getattr(fileops, function)(src, str(tmp_path / "dest"), skip_on_error = True, error_log_path = str(log))
    assert read(log) == os.path.join(src, "a.txt") + "\n"
    assert read(tmp_path / "dest" / "sub" / "b.txt") == "b"


@pytest.mark.parametrize("function,moves", BULK)
def test_bulk_transfer_skips_failed_directories(tmp_path, monkeypatch, function, moves):
    src = make_source(tmp_path / "src")
    monkeypatch.setattr(fileops, "make_directory", lambda **kwargs: False)
    assert getattr(fileops, function)(src, str(tmp_path / "dest"), skip_on_error = True)


@pytest.mark.parametrize("function,moves", GLOBBED)
def test_globbed_transfer_takes_only_matches(tmp_path, function, moves):
    write(tmp_path / "src" / "a.txt", "a")
    write(tmp_path / "src" / "b.log", "b")
    dest = tmp_path / "dest"
    assert getattr(fileops, function)(str(tmp_path / "src" / "*.txt"), str(dest), verbose = True)
    assert tree(dest) == {"a.txt"}
    assert (tmp_path / "src" / "a.txt").exists() is not moves


@pytest.mark.parametrize("function,moves", GLOBBED)
def test_globbed_transfer_stops_at_a_failure(tmp_path, monkeypatch, function, moves):
    write(tmp_path / "src" / "a.txt")
    pattern = str(tmp_path / "src" / "*.txt")
    monkeypatch.setattr(fileops, "transfer_file", lambda **kwargs: False)
    assert not getattr(fileops, function)(pattern, str(tmp_path / "dest"))
    monkeypatch.setattr(fileops, "make_directory", lambda **kwargs: False)
    assert not getattr(fileops, function)(pattern, str(tmp_path / "dest"))


@pytest.mark.parametrize("function,moves", GLOBBED)
def test_globbed_transfer_skips_failures_and_logs_them(tmp_path, monkeypatch, function, moves):
    src = write(tmp_path / "src" / "a.txt")
    pattern = str(tmp_path / "src" / "*.txt")
    log = tmp_path / "errors.txt"
    monkeypatch.setattr(fileops, "transfer_file", lambda **kwargs: False)
    assert getattr(fileops, function)(pattern, str(tmp_path / "dest"), skip_on_error = True, error_log_path = str(log))
    monkeypatch.setattr(fileops, "make_directory", lambda **kwargs: False)
    assert getattr(fileops, function)(pattern, str(tmp_path / "dest"), skip_on_error = True, error_log_path = str(log))
    assert read(log) == src + "\n" + src + "\n"


###########################################################
# Smart transfer
###########################################################

@pytest.mark.parametrize("delete_afterwards", [False, True])
def test_smart_transfer_of_a_file(tmp_path, delete_afterwards):
    src = write(tmp_path / "src.txt", "data")
    dest = tmp_path / "out" / "dest.txt"
    assert fileops.smart_transfer(src, str(dest), delete_afterwards = delete_afterwards)
    assert read(dest) == "data"
    assert os.path.exists(src) is not delete_afterwards


@pytest.mark.parametrize("delete_afterwards", [False, True])
def test_smart_transfer_of_a_directory(tmp_path, delete_afterwards):
    src = make_source(tmp_path / "src")
    dest = tmp_path / "dest"
    assert fileops.smart_transfer(src, str(dest), delete_afterwards = delete_afterwards)
    assert read(dest / "sub" / "b.txt") == "b"
    assert os.path.exists(os.path.join(src, "a.txt")) is not delete_afterwards


@pytest.mark.parametrize("delete_afterwards", [False, True])
def test_smart_transfer_of_a_glob(tmp_path, delete_afterwards):
    write(tmp_path / "src" / "a.txt", "a")
    write(tmp_path / "src" / "b.log", "b")
    dest = tmp_path / "dest"
    assert fileops.smart_transfer(str(tmp_path / "src" / "*.txt"), str(dest), delete_afterwards = delete_afterwards)
    assert tree(dest) == {"a.txt"}


@pytest.mark.parametrize("function", ["smart_copy", "smart_move"])
def test_smart_transfer_needs_the_destination_parent(tmp_path, monkeypatch, function):
    src = write(tmp_path / "src.txt")
    monkeypatch.setattr(fileops, "make_directory", lambda **kwargs: False)
    assert not getattr(fileops, function)(src, str(tmp_path / "dest.txt"))


###########################################################
# Sync
###########################################################

def test_sync_contents_replaces_the_destination(tmp_path):
    src = make_source(tmp_path / "src")
    dest = tmp_path / "dest"
    write(dest / "stale.txt")
    assert fileops.sync_contents(src, str(dest))
    assert tree(dest) == {"a.txt", "sub", os.path.join("sub", "b.txt")}


def test_sync_contents_of_a_missing_source_exits_when_asked(tmp_path):
    with pytest.raises(SystemExit):
        fileops.sync_contents(str(tmp_path / "missing"), str(tmp_path / "dest"), exit_on_failure = True)


@pytest.mark.parametrize("failing", ["make_directory", "remove_directory_contents"])
def test_sync_contents_stops_at_a_failure(tmp_path, monkeypatch, failing):
    src = make_source(tmp_path / "src")
    monkeypatch.setattr(fileops, failing, lambda **kwargs: False)
    assert not fileops.sync_contents(src, str(tmp_path / "dest"))


def test_sync_data_of_a_directory(tmp_path):
    src = make_source(tmp_path / "src")
    assert fileops.sync_data(src, str(tmp_path / "dest"))
    assert read(tmp_path / "dest" / "a.txt") == "a"


def test_sync_data_of_a_file(tmp_path):
    src = write(tmp_path / "src.txt", "data")
    assert fileops.sync_data(src, str(tmp_path / "out" / "dest.txt"))
    assert read(tmp_path / "out" / "dest.txt") == "data"


def test_sync_data_of_a_glob(tmp_path):
    write(tmp_path / "src" / "a.sav", "a")
    write(tmp_path / "src" / "b.txt", "b")
    assert fileops.sync_data(str(tmp_path / "src" / "*.sav"), str(tmp_path / "dest" / "*.sav"))
    assert tree(tmp_path / "dest") == {"a.sav"}


def test_sync_data_of_a_missing_source(tmp_path):
    src = str(tmp_path / "missing")
    assert not fileops.sync_data(src, str(tmp_path / "dest"))
    with pytest.raises(SystemExit):
        fileops.sync_data(src, str(tmp_path / "dest"), exit_on_failure = True)
