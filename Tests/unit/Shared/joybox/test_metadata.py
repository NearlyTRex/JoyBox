# Imports
import pytest

# Local imports
from joybox import config, metadata, metadataentry


###########################################################
# Metadata database
#
# The in-memory index of every scraped game, keyed by platform and name.
# set_game merges into an existing entry rather than replacing it, so a
# collector that revisits a game must not lose what was already known.
###########################################################

PLATFORM = config.Platform.NINTENDO_64
OTHER_PLATFORM = config.Platform.NINTENDO_GAMECUBE


def entry(game = "Chrono Trigger", platform = PLATFORM, **extra):
    built = metadataentry.MetadataEntry()
    built.set_game(game)
    built.set_platform(platform)
    built.set_file("game.z64")
    for key, value in extra.items():
        built.set_value(key, value)
    return built


def build(*entries):
    database = metadata.Metadata()
    for item in entries:
        database.add_game(item)
    return database


###########################################################
# Adding
###########################################################

def test_a_complete_entry_is_added():
    database = build(entry())

    assert database.has_game(PLATFORM, "Chrono Trigger") is True


def test_an_incomplete_entry_is_ignored():
    # Without the minimum keys there is nothing to index it under.
    incomplete = metadataentry.MetadataEntry()
    incomplete.set_game("Nameless")

    database = build(incomplete)

    assert database.get_sorted_platforms() == []


def test_adding_injects_the_categories():
    database = build(entry())
    stored = database.get_game(PLATFORM, "Chrono Trigger")

    assert stored.get_supercategory() == config.Supercategory.ROMS
    assert stored.get_category() is not None
    assert stored.get_subcategory() is not None


def test_a_missing_game_is_not_reported_present():
    database = build(entry())

    assert database.has_game(PLATFORM, "Absent") is False
    assert database.has_game(OTHER_PLATFORM, "Chrono Trigger") is False
    assert database.get_game(PLATFORM, "Absent") is None


###########################################################
# Merging on re-add
###########################################################

def test_re_adding_a_game_fills_gaps():
    database = build(entry(genre = "RPG"))
    database.add_game(entry(developer = "Square"))

    stored = database.get_game(PLATFORM, "Chrono Trigger")
    assert stored.get_value("genre") == "RPG"
    assert stored.get_value("developer") == "Square"


def test_re_adding_does_not_overwrite_what_is_known():
    database = build(entry(genre = "RPG"))
    database.add_game(entry(genre = "Adventure"))

    assert database.get_game(PLATFORM, "Chrono Trigger").get_value("genre") == "RPG"


def test_re_adding_does_not_alias_the_incoming_entry():
    # merge returns its first argument, so without a copy the stored entry and
    # the caller's would become one object.
    database = build(entry(genre = "RPG"))
    incoming = entry(developer = "Square")
    database.add_game(incoming)

    stored = database.get_game(PLATFORM, "Chrono Trigger")
    stored.set_value("later", "value")

    assert incoming.is_key_set("later") is False


def test_a_reused_entry_does_not_leak_between_games():
    # A collector looping over games with one entry object would otherwise
    # alias every stored game together.
    database = metadata.Metadata()
    database.add_game(entry("First"))
    database.add_game(entry("Second"))
    database.add_game(entry("First", genre = "RPG"))

    assert database.get_game(PLATFORM, "Second").is_key_set("genre") is False


###########################################################
# Ordering
###########################################################

def test_platforms_are_sorted():
    database = build(entry("A", OTHER_PLATFORM), entry("B", PLATFORM))

    assert database.get_sorted_platforms() == sorted(database.get_sorted_platforms())


def test_names_are_sorted_within_a_platform():
    database = build(entry("Zelda"), entry("Actraiser"), entry("Mario"))

    assert database.get_sorted_names(PLATFORM) == ["Actraiser", "Mario", "Zelda"]


def test_names_for_an_unknown_platform_are_empty():
    assert build(entry()).get_sorted_names(OTHER_PLATFORM) == []


def test_all_names_span_every_platform():
    database = build(entry("A", PLATFORM), entry("B", OTHER_PLATFORM))

    assert sorted(database.get_all_sorted_names()) == ["A", "B"]


def test_entries_follow_the_name_order():
    database = build(entry("Zelda"), entry("Actraiser"))
    entries = database.get_sorted_entries(PLATFORM)

    assert [item.get_game() for item in entries] == ["Actraiser", "Zelda"]


def test_all_entries_span_every_platform():
    database = build(entry("A", PLATFORM), entry("B", OTHER_PLATFORM))

    assert len(database.get_all_sorted_entries()) == 2


###########################################################
# Missing data
###########################################################

def test_an_entry_with_every_key_is_not_missing_data():
    database = build(entry(genre = "RPG"))

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is False


def test_an_absent_key_counts_as_missing():
    database = build(entry())

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is True


def test_an_empty_value_counts_as_missing():
    # An empty string is a placeholder, not data.
    database = build(entry(genre = ""))

    assert database.is_entry_missing_data(PLATFORM, "Chrono Trigger", ["genre"]) is True


def test_the_database_reports_missing_data_anywhere():
    database = build(entry("A", genre = "RPG"), entry("B"))

    assert database.is_missing_data(["genre"]) is True


def test_a_complete_database_reports_nothing_missing():
    database = build(entry("A", genre = "RPG"), entry("B", genre = "Action"))

    assert database.is_missing_data(["genre"]) is False


def test_an_empty_database_reports_nothing_missing():
    assert metadata.Metadata().is_missing_data(["genre"]) is False


###########################################################
# Merging databases
###########################################################

def test_merging_takes_games_from_the_other_database():
    first = build(entry("A"))
    second = build(entry("B"))
    first.merge_contents(second)

    assert sorted(first.get_all_sorted_names()) == ["A", "B"]


def test_merging_does_not_change_the_other_database():
    first = build(entry("A"))
    second = build(entry("B"))
    first.merge_contents(second)

    assert second.get_all_sorted_names() == ["B"]


def test_merging_an_empty_database_changes_nothing():
    first = build(entry("A"))
    first.merge_contents(metadata.Metadata())

    assert first.get_all_sorted_names() == ["A"]


###########################################################
# Random selection
###########################################################

def test_a_random_entry_comes_from_the_database():
    database = build(entry("A"), entry("B"))
    picked = database.get_random_entry()

    assert picked.get_game() in ["A", "B"]


def test_a_random_entry_from_an_empty_database_is_none():
    assert metadata.Metadata().get_random_entry() is None


def test_a_random_entry_skips_platforms_without_entries():
    database = build(entry("A"))
    database.game_database["Empty Platform"] = {}

    for _ in range(20):
        assert database.get_random_entry().get_game() == "A"


def test_a_database_of_only_empty_platforms_has_no_random_entry():
    database = metadata.Metadata()
    database.game_database["Empty Platform"] = {}

    assert database.get_random_entry() is None


def test_merging_honours_an_explicit_merge_type():
    first = build(entry("A"))
    first.merge_contents(build(entry("B")), merge_type = config.MergeType.ADDITIVE)

    assert first.get_all_sorted_names() == ["A", "B"]


def test_syncing_assets_reaches_every_entry(monkeypatch):
    synced = []
    monkeypatch.setattr(metadataentry.MetadataEntry, "sync_assets",
                        lambda self: synced.append(self.get_game()))
    build(entry("A"), entry("B", OTHER_PLATFORM)).sync_assets()

    assert sorted(synced) == ["A", "B"]


###########################################################
# Verifying files
###########################################################

@pytest.fixture
def metadata_root(tmp_path, monkeypatch):
    monkeypatch.setattr(metadata.environment, "get_game_json_metadata_root_dir",
                        lambda: str(tmp_path))
    errors = []
    monkeypatch.setattr(metadata.logger, "log_error",
                        lambda message, **kwargs: errors.append((message, kwargs)))
    return tmp_path, errors


def test_verifying_present_files_reports_nothing(metadata_root):
    root, errors = metadata_root
    (root / "game.z64").write_text("")
    build(entry("A")).verify_files(verbose = True)

    assert errors == []


def test_verifying_a_missing_file_quits(metadata_root):
    _, errors = metadata_root
    build(entry("A")).verify_files()

    assert "game.z64" in errors[0][0]
    assert errors[-1][1] == {"quit_program": True}


###########################################################
# Pegasus files
###########################################################

FULL_FIELDS = {
    "developer": "Square",
    "publisher": "Nintendo",
    "genre": "RPG",
    "release": "1995",
    "players": "1",
    "boxfront": "front.png",
    "boxback": "back.png",
    "background": "bg.png",
    "screenshot": "shot.png",
    "video": "clip.mp4",
    "url": "https://example.com/game",
    "coop": "No",
    "playable": "Yes",
}


def full_entry(game = "Chrono Trigger"):
    built = entry(game)
    for key, value in FULL_FIELDS.items():
        getattr(built, "set_" + key)(value)
    built.set_description(["First line.", "Second line."])
    return built


def test_a_pegasus_export_round_trips_every_field(tmp_path):
    path = str(tmp_path / "sub" / "metadata.pegasus.txt")
    build(full_entry()).export_to_metadata_file(path)

    imported = metadata.Metadata()
    imported.import_from_metadata_file(path)
    stored = imported.get_game(PLATFORM, "Chrono Trigger")

    for key, value in FULL_FIELDS.items():
        assert getattr(stored, "get_" + key)() == value, key
    assert stored.get_description() == ["First line.", "Second line."]
    assert stored.get_file() == "game.z64"


def test_a_pegasus_export_omits_unset_fields(tmp_path):
    path = str(tmp_path / "metadata.pegasus.txt")
    build(entry()).export_to_pegasus_file(path)

    with open(path, encoding = "utf8") as handle:
        written = handle.read()
    assert "game: Chrono Trigger\nfile: game.z64\n\n\n" in written
    assert "developer:" not in written
    assert "x-playable:" not in written


def test_an_entry_without_a_game_or_file_writes_neither(tmp_path):
    database = metadata.Metadata()
    bare = metadataentry.MetadataEntry()
    database.set_game(PLATFORM, "Bare", bare)
    path = str(tmp_path / "metadata.pegasus.txt")
    database.export_to_pegasus_file(path)

    with open(path, encoding = "utf8") as handle:
        written = handle.read()
    assert "game:" not in written
    assert "file:" not in written


def test_appending_keeps_the_existing_export(tmp_path):
    path = str(tmp_path / "metadata.pegasus.txt")
    build(entry("A")).export_to_pegasus_file(path)
    build(entry("B")).export_to_pegasus_file(path, append_existing = True)

    with open(path, encoding = "utf8") as handle:
        written = handle.read()
    assert "game: A" in written and "game: B" in written


def test_a_tag_line_is_skipped_and_ends_the_description(tmp_path):
    path = tmp_path / "metadata.pegasus.txt"
    path.write_text(
        "# exported\ncollection: %s\n\n\ngame: A\nfile: a.z64\n"
        "description:\n  Kept.\ntag: favourite\n  Not description.\n" % PLATFORM.val(),
        encoding = "utf8")
    database = metadata.Metadata()
    database.import_from_pegasus_file(str(path))

    assert database.get_game(PLATFORM, "A").get_description() == ["Kept."]


def test_a_file_without_a_collection_header_imports_nothing(tmp_path):
    path = tmp_path / "metadata.pegasus.txt"
    path.write_text("game: A\nfile: a.z64\n", encoding = "utf8")
    database = metadata.Metadata()
    database.import_from_pegasus_file(str(path))

    assert database.get_sorted_platforms() == []


def test_importing_a_missing_file_imports_nothing(tmp_path):
    database = metadata.Metadata()
    database.import_from_pegasus_file(str(tmp_path / "absent.txt"))

    assert database.get_sorted_platforms() == []


def test_an_unknown_metadata_format_is_neither_read_nor_written(tmp_path):
    path = str(tmp_path / "metadata.txt")
    database = build(entry())
    database.export_to_metadata_file(path, metadata_format = None)
    database.import_from_metadata_file(path, metadata_format = None)

    assert not (tmp_path / "metadata.txt").exists()


def test_an_unknown_platform_has_no_games():
    assert build(entry()).get_game(OTHER_PLATFORM, "Chrono Trigger") is None
