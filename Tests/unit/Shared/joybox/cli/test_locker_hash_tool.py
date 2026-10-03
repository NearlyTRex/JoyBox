# Imports
import os
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import hashing, system
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
                     "Photos/Trip/a.jpg", "Gaming/Roms/game.iso", ".hidden/secret.txt",
                     "Documents/.cache/blob", "top.txt"]:
        path = root / relative
        path.parent.mkdir(parents = True, exist_ok = True)
        path.write_text(relative)
    metadata = tmp_path / "Metadata"
    isolated_settings.set_value("UserData.Dirs", "file_metadata_dir", str(metadata))
    monkeypatch.setattr(locker_hash_tool.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(locker_hash_tool.logger, "setup_logging", lambda: None)
    errors = []
    log_error = locker_hash_tool.logger.log_error

    def record_error(message, **kwargs):
        errors.append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(locker_hash_tool.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["locker_hash_tool", "-l", str(root), *extra])
        return system.run_main(locker_hash_tool.main)

    return {"root": root, "hashes": metadata / "Locker" / "Hashes", "run": run, "errors": errors}


def hashed_files(hashes_dir):
    found = {}
    for dirpath, _, filenames in os.walk(hashes_dir):
        for filename in filenames:
            csv_path = os.path.join(dirpath, filename)
            relative = os.path.relpath(csv_path, hashes_dir)
            found[relative] = sorted(hashing.read_hash_file_csv(csv_path).keys())
    return found


def test_default_filters_skip_hidden_and_excluded_files(locker):
    locker["run"]()

    assert hashed_files(locker["hashes"]) == {
        os.path.join("Documents", "Taxes.csv"): ["Documents/Taxes/2024/return.pdf", "Documents/Taxes/notes.txt"],
        os.path.join("Photos", "Trip.csv"): ["Photos/Trip/a.jpg"],
        "root.csv": ["top.txt"],
    }
    assert locker["errors"] == []


def test_include_filter_and_hidden_files(locker):
    locker["run"]("-i", "Documents/*, ", "-e", "", "--include_hidden", "-d", "1")

    assert hashed_files(locker["hashes"]) == {
        "Documents.csv": ["Documents/.cache/blob", "Documents/Taxes/2024/return.pdf", "Documents/Taxes/notes.txt"],
    }


def test_rows_for_deleted_files_are_dropped(locker):
    locker["run"]()
    os.remove(locker["root"] / "Documents" / "Taxes" / "notes.txt")

    locker["run"]()

    taxes = hashed_files(locker["hashes"])[os.path.join("Documents", "Taxes.csv")]
    assert taxes == ["Documents/Taxes/2024/return.pdf"]


def test_pretend_run_writes_nothing(locker):
    locker["run"]("-p")

    assert not locker["hashes"].exists()


def test_missing_locker_exits_with_an_error(locker, monkeypatch, tmp_path):
    missing = tmp_path / "Nowhere"
    monkeypatch.setattr(sys, "argv", ["locker_hash_tool", "-l", str(missing)])

    with pytest.raises(SystemExit) as raised:
        system.run_main(locker_hash_tool.main)
    assert raised.value.code != 0
    assert locker["errors"] == ["Base directory does not exist: %s" % missing]


def test_failed_hash_write_exits_with_an_error(locker, monkeypatch):
    monkeypatch.setattr(locker_hash_tool.hashing, "hash_files", lambda **kwargs: False)
    cleaned = []
    monkeypatch.setattr(locker_hash_tool.hashing, "clean_missing_hash_entries",
                        lambda **kwargs: cleaned.append(kwargs["hash_file"]) or True)

    with pytest.raises(SystemExit) as raised:
        locker["run"]()
    assert raised.value.code == 1
    assert locker["errors"][-1] == "3 hash files could not be written"
    assert cleaned == []


def test_failed_clean_exits_with_an_error(locker, monkeypatch):
    monkeypatch.setattr(locker_hash_tool.hashing, "clean_missing_hash_entries", lambda **kwargs: False)

    with pytest.raises(SystemExit) as raised:
        locker["run"]("-i", "top.txt")
    assert raised.value.code == 1
    assert locker["errors"] == [
        "Failed to clean: %s" % (locker["hashes"] / "root.csv"),
        "1 hash files could not be written",
    ]


def test_run_goes_through_the_shared_error_handling(locker, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["locker_hash_tool", "-l", str(locker["root"]), "-p"])

    locker_hash_tool.run()

    assert locker["errors"] == []


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", lambda main: called.append(main))

    runpy.run_path(locker_hash_tool.__file__, run_name = "__main__")

    assert len(called) == 1
