# Imports
import os

# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import hashing
from joybox.cli import locker_hash_tool


###########################################################
# Locker hashing
#
# Runs the real hashing against a small locker in tmp_path, writing CSVs into a
# scratch file_metadata_dir.
###########################################################

@pytest.fixture
def locker(tmp_path, monkeypatch, isolated_settings):
    root = tmp_path / "Locker"
    for relative in ["Documents/Taxes/2024/return.pdf", "Documents/Taxes/notes.txt",
                     "Photos/Trip/a.jpg", "Photos/b.jpg", "Gaming/Roms/game.iso", ".hidden/secret.txt",
                     "Documents/.cache/blob", "top.txt"]:
        path = root / relative
        path.parent.mkdir(parents = True, exist_ok = True)
        path.write_text(relative)
    metadata = tmp_path / "Metadata"
    isolated_settings.set_value("UserData.Dirs", "file_metadata_dir", str(metadata))
    harness = CommandHarness(monkeypatch, locker_hash_tool)
    harness.root = root
    harness.hashes = metadata / "Locker" / "Hashes"
    return harness


def hashed_files(hashes_dir):
    found = {}
    for dirpath, _, filenames in os.walk(hashes_dir):
        for filename in filenames:
            csv_path = os.path.join(dirpath, filename)
            relative = os.path.relpath(csv_path, hashes_dir)
            found[relative] = sorted(hashing.read_hash_file_csv(csv_path).keys())
    return found


def test_default_filters_skip_hidden_and_excluded_files(locker):
    locker.run("-l", str(locker.root))

    assert hashed_files(locker.hashes) == {
        os.path.join("Documents", "Taxes.csv"): ["Documents/Taxes/2024/return.pdf", "Documents/Taxes/notes.txt"],
        os.path.join("Photos", "Trip.csv"): ["Photos/Trip/a.jpg"],
        "Photos.csv": ["Photos/b.jpg"],
        "root.csv": ["top.txt"],
    }
    assert locker.errors == []


def test_depth_one_gives_one_csv_per_top_level_folder(locker):
    locker.run("-l", str(locker.root), "-e", "", "-d", "1")

    assert sorted(hashed_files(locker.hashes)) == ["Documents.csv", "Gaming.csv", "Photos.csv", "root.csv"]


def test_a_file_shallower_than_the_depth_uses_the_folders_it_has(locker):
    locker.run("-l", str(locker.root), "-i", "Documents/*", "-d", "3")

    assert hashed_files(locker.hashes) == {
        os.path.join("Documents", "Taxes", "2024.csv"): ["Documents/Taxes/2024/return.pdf"],
        os.path.join("Documents", "Taxes.csv"): ["Documents/Taxes/notes.txt"],
    }


def test_a_depth_below_one_is_refused(locker):
    assert locker.exit_code("-l", str(locker.root), "-d", "0") != 0
    assert locker.errors == ["Depth must be at least 1"]
    assert not locker.hashes.exists()


def test_include_filter_and_hidden_files(locker):
    locker.run("-l", str(locker.root), "-i", "Documents/*, ", "-e", "", "--include_hidden", "-d", "1")

    assert hashed_files(locker.hashes) == {
        "Documents.csv": ["Documents/.cache/blob", "Documents/Taxes/2024/return.pdf", "Documents/Taxes/notes.txt"],
    }


def test_rows_for_deleted_files_are_dropped(locker):
    locker.run("-l", str(locker.root))
    os.remove(locker.root / "Documents" / "Taxes" / "notes.txt")

    locker.run("-l", str(locker.root))

    taxes = hashed_files(locker.hashes)[os.path.join("Documents", "Taxes.csv")]
    assert taxes == ["Documents/Taxes/2024/return.pdf"]


def test_pretend_run_writes_nothing(locker):
    locker.run("-l", str(locker.root), "-p")

    assert not locker.hashes.exists()


def test_missing_locker_exits_with_an_error(locker, tmp_path):
    missing = tmp_path / "Nowhere"

    assert locker.exit_code("-l", str(missing)) != 0
    assert locker.errors == ["Base directory does not exist: %s" % missing]


def test_failed_hash_write_exits_with_an_error(locker, monkeypatch):
    monkeypatch.setattr(locker_hash_tool.hashing, "hash_files", lambda **kwargs: False)
    cleaned = []
    monkeypatch.setattr(locker_hash_tool.hashing, "clean_missing_hash_entries",
                        lambda **kwargs: cleaned.append(kwargs["hash_file"]) or True)

    assert locker.exit_code("-l", str(locker.root)) == 1
    assert locker.errors[-1] == "4 hash files could not be written"
    assert cleaned == []


def test_failed_clean_exits_with_an_error(locker, monkeypatch):
    monkeypatch.setattr(locker_hash_tool.hashing, "clean_missing_hash_entries", lambda **kwargs: False)

    assert locker.exit_code("-l", str(locker.root), "-i", "top.txt") == 1
    assert locker.errors == [
        "Failed to clean: %s" % (locker.hashes / "root.csv"),
        "1 hash files could not be written",
    ]


def test_run_goes_through_the_shared_error_handling(locker):
    locker.run("-l", str(locker.root), "-p")

    assert locker.errors == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, locker_hash_tool)
