# Imports
import pytest

# Local imports
from joybox import sqlitedb


###########################################################
# Database
#
# The hash database backs sync's change detection, so a row that is written but
# not committed, or a query that matches more paths than it was asked for, is a
# wrong sync decision.
###########################################################

@pytest.fixture
def database(tmp_path):
    db = sqlitedb.Database(str(tmp_path / "test.db"))
    db.open()
    db.create_table("games", {"name": "TEXT PRIMARY KEY", "platform": "TEXT", "size": "INTEGER"})
    yield db
    db.close()


@pytest.fixture
def hashes(tmp_path):
    db = sqlitedb.HashDatabase(str(tmp_path / "hashes.db"))
    db.open()
    db.initialize()
    yield db
    db.close()


def names(rows):
    return [row["name"] for row in rows]


###########################################################
# Connections
###########################################################

def test_a_database_file_is_created(tmp_path):
    target = tmp_path / "test.db"
    db = sqlitedb.Database(str(target))
    db.open()
    db.create_table("games", {"name": "TEXT"})
    db.close()

    assert target.exists()


def test_a_missing_parent_directory_is_created(tmp_path):
    target = tmp_path / "nested" / "deeper" / "test.db"
    db = sqlitedb.Database(str(target))
    db.open()
    db.create_table("games", {"name": "TEXT"})
    db.close()

    assert target.exists()


def test_a_database_works_as_a_context_manager(tmp_path):
    with sqlitedb.Database(str(tmp_path / "test.db")) as db:
        db.create_table("games", {"name": "TEXT"})
        assert db.table_exists("games") is True


def test_an_exception_inside_the_context_is_not_swallowed(tmp_path):
    with pytest.raises(ValueError):
        with sqlitedb.Database(str(tmp_path / "test.db")) as db:
            raise ValueError("boom")


def test_reopening_returns_the_same_connection(tmp_path):
    db = sqlitedb.Database(str(tmp_path / "test.db"))
    first = db.open()
    second = db.open()

    assert first is second
    db.close()


def test_two_handles_on_one_file_share_a_connection(tmp_path):
    # Connections are pooled by path, so a second handle must not open a rival
    # write transaction against the same file.
    target = str(tmp_path / "test.db")
    first = sqlitedb.Database(target)
    second = sqlitedb.Database(target)

    assert first.open() is second.open()
    first.close()


def test_closing_twice_is_harmless(tmp_path):
    db = sqlitedb.Database(str(tmp_path / "test.db"))
    db.open()
    db.close()
    db.close()


def test_closing_without_opening_is_harmless(tmp_path):
    sqlitedb.Database(str(tmp_path / "test.db")).close()


###########################################################
# Tables
###########################################################

def test_a_table_is_created(database):
    assert database.table_exists("games") is True


def test_an_unknown_table_is_absent(database):
    assert database.table_exists("not_a_table") is False


def test_creating_a_table_twice_is_harmless(database):
    database.create_table("games", {"name": "TEXT PRIMARY KEY"})

    assert database.table_exists("games") is True


def test_a_primary_key_is_enforced(database):
    database.insert("games", {"name": "Doom"})

    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        database.insert("games", {"name": "Doom"})


def test_an_index_is_created(database):
    database.create_index("idx_platform", "games", "platform")
    rows = database.fetch_all(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_platform'")

    assert len(rows) == 1


def test_an_index_spans_several_columns(database):
    database.create_index("idx_pair", "games", ["platform", "size"])
    row = database.fetch_one(
        "SELECT sql FROM sqlite_master WHERE name='idx_pair'")

    assert "platform" in row["sql"] and "size" in row["sql"]


def test_a_unique_index_rejects_duplicates(database):
    database.create_index("idx_platform", "games", "platform", unique = True)
    database.insert("games", {"name": "Doom", "platform": "DOS"})

    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        database.insert("games", {"name": "Quake", "platform": "DOS"})


###########################################################
# Rows
###########################################################

def test_a_row_is_inserted_and_read_back(database):
    database.insert("games", {"name": "Doom", "platform": "DOS", "size": 100})
    row = database.fetch_one("SELECT * FROM games WHERE name = ?", ("Doom",))

    assert row["platform"] == "DOS"
    assert row["size"] == 100


def test_a_replacing_insert_overwrites(database):
    database.insert("games", {"name": "Doom", "platform": "DOS"})
    database.insert("games", {"name": "Doom", "platform": "Windows"}, or_replace = True)

    assert database.count("games") == 1
    assert database.fetch_one("SELECT * FROM games")["platform"] == "Windows"


def test_many_rows_are_inserted(database):
    database.insert_many("games", ["name", "platform"], [
        ("Doom", "DOS"), ("Quake", "DOS"), ("Halo", "Xbox")])

    assert database.count("games") == 3


def test_inserting_no_rows_is_harmless(database):
    database.insert_many("games", ["name"], [])

    assert database.count("games") == 0


def test_a_row_is_updated(database):
    database.insert("games", {"name": "Doom", "platform": "DOS"})
    database.update("games", {"platform": "Windows"}, "name = ?", ("Doom",))

    assert database.fetch_one("SELECT * FROM games")["platform"] == "Windows"


def test_an_update_touches_only_matching_rows(database):
    database.insert_many("games", ["name", "platform"], [("Doom", "DOS"), ("Halo", "Xbox")])
    database.update("games", {"platform": "Windows"}, "name = ?", ("Doom",))

    assert database.fetch_one("SELECT * FROM games WHERE name = 'Halo'")["platform"] == "Xbox"


def test_a_row_is_deleted(database):
    database.insert_many("games", ["name"], [("Doom",), ("Quake",)])
    database.delete("games", "name = ?", ("Doom",))

    assert names(database.select("games")) == ["Quake"]


def test_deleting_without_a_clause_empties_the_table(database):
    database.insert_many("games", ["name"], [("Doom",), ("Quake",)])
    database.delete("games")

    assert database.count("games") == 0


###########################################################
# Selecting
###########################################################

@pytest.fixture
def stocked(database):
    database.insert_many("games", ["name", "platform", "size"], [
        ("Doom", "DOS", 30),
        ("Quake", "DOS", 20),
        ("Halo", "Xbox", 10),
    ])
    return database


def test_every_row_is_selected(stocked):
    assert sorted(names(stocked.select("games"))) == ["Doom", "Halo", "Quake"]


def test_selected_columns_are_narrowed(stocked):
    row = stocked.select("games", columns = ["name"])[0]

    assert list(row.keys()) == ["name"]


def test_a_column_string_is_accepted(stocked):
    row = stocked.select("games", columns = "name, platform")[0]

    assert sorted(row.keys()) == ["name", "platform"]


def test_a_where_clause_filters(stocked):
    rows = stocked.select("games", where_clause = "platform = ?", where_params = ("DOS",))

    assert sorted(names(rows)) == ["Doom", "Quake"]


def test_an_order_is_applied(stocked):
    assert names(stocked.select("games", order_by = "size ASC")) == ["Halo", "Quake", "Doom"]


def test_a_limit_is_applied(stocked):
    assert len(stocked.select("games", limit = 2)) == 2


def test_a_limit_applies_after_ordering(stocked):
    assert names(stocked.select("games", order_by = "size DESC", limit = 1)) == ["Doom"]


def test_rows_are_counted(stocked):
    assert stocked.count("games") == 3


def test_a_filtered_count_is_narrowed(stocked):
    assert stocked.count("games", "platform = ?", ("DOS",)) == 2


def test_an_empty_table_counts_zero(database):
    assert database.count("games") == 0


def test_a_missing_row_fetches_as_none(stocked):
    assert stocked.fetch_one("SELECT * FROM games WHERE name = ?", ("Myst",)) is None


###########################################################
# Transactions
###########################################################

def test_a_rollback_discards_uncommitted_rows(database):
    database.insert("games", {"name": "Doom"})
    database.rollback()

    assert database.count("games") == 0


def test_a_commit_survives_a_rollback(database):
    database.insert("games", {"name": "Doom"})
    database.commit()
    database.rollback()

    assert database.count("games") == 1


def test_committed_rows_survive_a_reopen(tmp_path):
    target = str(tmp_path / "test.db")
    db = sqlitedb.Database(target)
    db.open()
    db.create_table("games", {"name": "TEXT"})
    db.insert("games", {"name": "Doom"})
    db.commit()
    db.close()

    reopened = sqlitedb.Database(target)
    reopened.open()
    assert reopened.count("games") == 1
    reopened.close()


###########################################################
# HashDatabase
###########################################################

def test_the_hash_table_is_initialized(hashes):
    assert hashes.table_exists(sqlitedb.HashDatabase.TABLE_NAME) is True


def test_initializing_twice_is_harmless(hashes):
    hashes.initialize()

    assert hashes.get_count() == 0


def test_a_hash_is_stored_and_read_back(hashes):
    hashes.set_hash("/games/doom.zip", "abc123", size = 100, mtime = 1.5)
    entry = hashes.get_hash("/games/doom.zip")

    assert entry["hash"] == "abc123"
    assert entry["size"] == 100
    assert entry["mtime"] == 1.5


def test_a_stored_hash_is_timestamped(hashes):
    hashes.set_hash("/games/doom.zip", "abc123")

    assert hashes.get_hash("/games/doom.zip")["updated_at"] > 0


def test_a_hash_is_stored_without_size_or_mtime(hashes):
    hashes.set_hash("/games/doom.zip", "abc123")
    entry = hashes.get_hash("/games/doom.zip")

    assert entry["size"] is None
    assert entry["mtime"] is None


def test_an_unknown_path_has_no_hash(hashes):
    assert hashes.get_hash("/games/absent.zip") is None
    assert hashes.has_hash("/games/absent.zip") is False


def test_a_stored_path_is_reported_present(hashes):
    hashes.set_hash("/games/doom.zip", "abc123")

    assert hashes.has_hash("/games/doom.zip") is True


def test_restoring_a_hash_overwrites_it(hashes):
    hashes.set_hash("/games/doom.zip", "abc123")
    hashes.set_hash("/games/doom.zip", "def456")

    assert hashes.get_count() == 1
    assert hashes.get_hash("/games/doom.zip")["hash"] == "def456"


def test_a_single_hash_survives_a_reopen(tmp_path):
    # set_hashes commits; the single-entry path must too, or a close discards
    # the row and the next sync rehashes the file.
    target = str(tmp_path / "hashes.db")
    db = sqlitedb.HashDatabase(target)
    db.open()
    db.initialize()
    db.set_hash("/games/doom.zip", "abc123")
    db.close()

    reopened = sqlitedb.HashDatabase(target)
    reopened.open()
    assert reopened.get_hash("/games/doom.zip")["hash"] == "abc123"
    reopened.close()


def test_a_deleted_hash_stays_deleted_after_a_reopen(tmp_path):
    target = str(tmp_path / "hashes.db")
    db = sqlitedb.HashDatabase(target)
    db.open()
    db.initialize()
    db.set_hashes([{"file_path": "/games/doom.zip", "hash": "abc123"}])
    db.delete_hash("/games/doom.zip")
    db.close()

    reopened = sqlitedb.HashDatabase(target)
    reopened.open()
    assert reopened.get_count() == 0
    reopened.close()


###########################################################
# Batches
###########################################################

def test_a_batch_of_hashes_is_stored(hashes):
    hashes.set_hashes([
        {"file_path": "/games/doom.zip", "hash": "abc", "size": 1, "mtime": 1.0},
        {"file_path": "/games/quake.zip", "hash": "def", "size": 2, "mtime": 2.0},
    ])

    assert hashes.get_count() == 2
    assert hashes.get_hash("/games/quake.zip")["hash"] == "def"


def test_a_batch_shares_one_timestamp(hashes):
    hashes.set_hashes([
        {"file_path": "/games/doom.zip", "hash": "abc"},
        {"file_path": "/games/quake.zip", "hash": "def"},
    ])
    stamps = {entry["updated_at"] for entry in hashes.get_all_hashes()}

    assert len(stamps) == 1


def test_an_empty_batch_is_harmless(hashes):
    hashes.set_hashes([])

    assert hashes.get_count() == 0


def test_a_batch_entry_may_omit_size_and_mtime(hashes):
    hashes.set_hashes([{"file_path": "/games/doom.zip", "hash": "abc"}])
    entry = hashes.get_hash("/games/doom.zip")

    assert entry["size"] is None
    assert entry["mtime"] is None


def test_a_batch_replaces_existing_paths(hashes):
    hashes.set_hash("/games/doom.zip", "abc")
    hashes.set_hashes([{"file_path": "/games/doom.zip", "hash": "def"}])

    assert hashes.get_count() == 1
    assert hashes.get_hash("/games/doom.zip")["hash"] == "def"


def test_every_stored_hash_is_listed(hashes):
    hashes.set_hashes([
        {"file_path": "/a", "hash": "1"},
        {"file_path": "/b", "hash": "2"},
    ])

    assert sorted(entry["file_path"] for entry in hashes.get_all_hashes()) == ["/a", "/b"]


def test_clearing_removes_everything(hashes):
    hashes.set_hashes([{"file_path": "/a", "hash": "1"}])
    hashes.clear_all()

    assert hashes.get_count() == 0


###########################################################
# Prefix queries
#
# Prefixes are literal directory paths. LIKE treats "_" as a single character
# wildcard and "%" as any run, and both appear in real library paths.
###########################################################

@pytest.fixture
def library(hashes):
    hashes.set_hashes([
        {"file_path": "/locker/Gaming/Games/doom.zip", "hash": "1"},
        {"file_path": "/locker/Gaming/Games/quake.zip", "hash": "2"},
        {"file_path": "/locker/Gaming/Saves/doom.sav", "hash": "3"},
        {"file_path": "/locker/Music/track.flac", "hash": "4"},
    ])
    return hashes


def test_a_prefix_selects_its_subtree(library):
    entries = library.get_hashes_by_prefix("/locker/Gaming/Games/")

    assert sorted(entry["file_path"] for entry in entries) == [
        "/locker/Gaming/Games/doom.zip",
        "/locker/Gaming/Games/quake.zip",
    ]


def test_a_prefix_counts_its_subtree(library):
    assert library.get_count_by_prefix("/locker/Gaming/") == 3


def test_a_prefix_matching_nothing_is_empty(library):
    assert library.get_hashes_by_prefix("/locker/Video/") == []
    assert library.get_count_by_prefix("/locker/Video/") == 0


def test_a_prefix_deletes_its_subtree(library):
    library.delete_hashes_by_prefix("/locker/Gaming/")

    assert sorted(entry["file_path"] for entry in library.get_all_hashes()) == [
        "/locker/Music/track.flac"]


def test_an_underscore_in_a_prefix_is_literal(hashes):
    hashes.set_hashes([
        {"file_path": "/data/save_games/a.sav", "hash": "1"},
        {"file_path": "/data/saveXgames/b.sav", "hash": "2"},
    ])
    entries = hashes.get_hashes_by_prefix("/data/save_games/")

    assert [entry["file_path"] for entry in entries] == ["/data/save_games/a.sav"]


def test_an_underscore_prefix_deletes_only_its_own_subtree(hashes):
    # The dangerous one: a wildcard here removes a sibling directory's hashes.
    hashes.set_hashes([
        {"file_path": "/data/save_games/a.sav", "hash": "1"},
        {"file_path": "/data/saveXgames/b.sav", "hash": "2"},
    ])
    hashes.delete_hashes_by_prefix("/data/save_games/")

    assert [entry["file_path"] for entry in hashes.get_all_hashes()] == ["/data/saveXgames/b.sav"]


def test_an_underscore_prefix_counts_only_its_own_subtree(hashes):
    hashes.set_hashes([
        {"file_path": "/data/save_games/a.sav", "hash": "1"},
        {"file_path": "/data/saveXgames/b.sav", "hash": "2"},
    ])

    assert hashes.get_count_by_prefix("/data/save_games/") == 1


def test_a_percent_in_a_prefix_is_literal(hashes):
    hashes.set_hashes([
        {"file_path": "/data/100%/a.bin", "hash": "1"},
        {"file_path": "/data/100pct/b.bin", "hash": "2"},
    ])
    entries = hashes.get_hashes_by_prefix("/data/100%/")

    assert [entry["file_path"] for entry in entries] == ["/data/100%/a.bin"]


def test_a_backslash_in_a_prefix_is_literal(hashes):
    # The escape character itself has to survive being a path character.
    hashes.set_hashes([
        {"file_path": "C:\\Games\\doom.zip", "hash": "1"},
        {"file_path": "C:\\Music\\track.flac", "hash": "2"},
    ])
    entries = hashes.get_hashes_by_prefix("C:\\Games\\")

    assert [entry["file_path"] for entry in entries] == ["C:\\Games\\doom.zip"]


@pytest.mark.parametrize("pattern,expected", [
    ("plain", "plain"),
    ("save_games", "save\\_games"),
    ("100%", "100\\%"),
    ("a_b%c", "a\\_b\\%c"),
    ("C:\\Games", "C:\\\\Games"),
    ("", ""),
])
def test_like_patterns_are_escaped(pattern, expected):
    assert sqlitedb.escape_like_pattern(pattern) == expected


###########################################################
# Dictionary interchange
###########################################################

def test_hashes_are_exported_to_a_dictionary(library):
    exported = library.export_to_dict()

    assert len(exported) == 4
    assert exported["/locker/Music/track.flac"]["hash"] == "4"


def test_an_export_carries_size_and_mtime(hashes):
    hashes.set_hashes([{"file_path": "/a", "hash": "1", "size": 10, "mtime": 2.5}])
    exported = hashes.export_to_dict()

    assert exported["/a"] == {"hash": "1", "size": 10, "mtime": 2.5}


def test_an_export_is_narrowed_by_prefix(library):
    exported = library.export_to_dict(prefix = "/locker/Gaming/Games/")

    assert sorted(exported) == [
        "/locker/Gaming/Games/doom.zip",
        "/locker/Gaming/Games/quake.zip",
    ]


def test_an_empty_database_exports_an_empty_dictionary(hashes):
    assert hashes.export_to_dict() == {}


def test_a_dictionary_is_imported(hashes):
    hashes.import_from_dict({
        "/a": {"hash": "1", "size": 10, "mtime": 2.5},
        "/b": {"hash": "2", "size": 20, "mtime": 3.5},
    })

    assert hashes.get_count() == 2
    assert hashes.get_hash("/b")["size"] == 20


def test_an_import_round_trips(hashes):
    original = {
        "/a": {"hash": "1", "size": 10, "mtime": 2.5},
        "/b": {"hash": "2", "size": 20, "mtime": 3.5},
    }
    hashes.import_from_dict(original)

    assert hashes.export_to_dict() == original


def test_an_imported_entry_may_omit_fields(hashes):
    hashes.import_from_dict({"/a": {"hash": "1"}})

    assert hashes.export_to_dict() == {"/a": {"hash": "1", "size": None, "mtime": None}}


def test_an_empty_import_is_harmless(hashes):
    hashes.import_from_dict({})

    assert hashes.get_count() == 0
