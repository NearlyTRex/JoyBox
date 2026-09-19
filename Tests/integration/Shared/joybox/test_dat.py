# Imports
import pytest

# Local imports
from joybox import config, dat


###########################################################
# Dat
#
# Keyed by md5 so imported rom databases can rename files by content. A game
# whose md5 is lost or mangled on import can never be matched.
###########################################################

def make_entry(game = "Chrono Trigger", file = "Chrono Trigger.sfc", size = "4194304",
               crc = "2d206bf7", md5 = "a2bc3f1e"):
    return {
        config.dat_key_game: game,
        config.dat_key_file: file,
        config.dat_key_size: size,
        config.dat_key_crc: crc,
        config.dat_key_md5: md5,
    }


def cache_line(entry):
    return " || ".join([
        entry[config.dat_key_game],
        entry[config.dat_key_file],
        entry[config.dat_key_size],
        entry[config.dat_key_crc],
        entry[config.dat_key_md5],
    ])


def write_cache(path, entries):
    with open(path, "w", encoding = "utf8", newline = "\n") as handle:
        for entry in entries:
            handle.write(cache_line(entry) + "\n")
    return str(path)


def write_xml(path, text):
    with open(path, "w", encoding = "utf8") as handle:
        handle.write(text)
    return str(path)


###########################################################
# Lookup
###########################################################

def test_a_game_is_found_by_its_md5():
    database = dat.Dat()
    database.add_game(make_entry(md5 = "abc123"))

    assert database.is_md5_present("abc123") is True
    assert database.get_by_md5("abc123")[config.dat_key_game] == "Chrono Trigger"


def test_an_unknown_md5_is_absent():
    database = dat.Dat()

    assert database.is_md5_present("abc123") is False
    assert database.get_by_md5("abc123") is None


def test_a_new_database_is_empty():
    assert dat.Dat().game_database == {}


def test_two_databases_do_not_share_entries():
    first = dat.Dat()
    first.add_game(make_entry(md5 = "abc123"))

    assert dat.Dat().is_md5_present("abc123") is False


def test_the_same_md5_is_stored_once():
    # Identical content under two names is one entry; the last import wins.
    database = dat.Dat()
    database.add_game(make_entry(game = "First", md5 = "abc123"))
    database.add_game(make_entry(game = "Second", md5 = "abc123"))

    assert len(database.game_database) == 1
    assert database.get_by_md5("abc123")[config.dat_key_game] == "Second"


def test_md5_lookup_is_case_sensitive():
    # Hashes arrive lowercase from hashing.calculate_file_md5, so an uppercase
    # dat entry would never match a scanned file.
    database = dat.Dat()
    database.add_game(make_entry(md5 = "ABC123"))

    assert database.is_md5_present("abc123") is False


###########################################################
# Cache dat files
###########################################################

def test_a_cache_dat_file_is_imported(tmp_path):
    source = write_cache(tmp_path / "cache.txt", [make_entry(md5 = "abc123")])
    database = dat.Dat()

    assert database.import_cache_dat_file(source) is True
    assert database.get_by_md5("abc123")[config.dat_key_file] == "Chrono Trigger.sfc"


def test_every_cache_field_survives_import(tmp_path):
    entry = make_entry()
    source = write_cache(tmp_path / "cache.txt", [entry])
    database = dat.Dat()
    database.import_cache_dat_file(source)

    assert database.get_by_md5(entry[config.dat_key_md5]) == entry


def test_a_short_cache_line_is_skipped(tmp_path):
    target = tmp_path / "cache.txt"
    with open(target, "w", encoding = "utf8") as handle:
        handle.write("Chrono Trigger || Chrono Trigger.sfc || 4194304\n")
        handle.write(cache_line(make_entry(md5 = "abc123")) + "\n")
    database = dat.Dat()

    assert database.import_cache_dat_file(str(target)) is True
    assert len(database.game_database) == 1


def test_a_blank_cache_line_is_skipped(tmp_path):
    target = tmp_path / "cache.txt"
    with open(target, "w", encoding = "utf8") as handle:
        handle.write("\n")
        handle.write(cache_line(make_entry(md5 = "abc123")) + "\n")
        handle.write("\n")
    database = dat.Dat()
    database.import_cache_dat_file(str(target))

    assert len(database.game_database) == 1


def test_a_missing_cache_dat_file_reports_failure(tmp_path):
    assert dat.Dat().import_cache_dat_file(str(tmp_path / "absent.txt")) is False


def test_importing_a_cache_dat_file_adds_to_the_database(tmp_path):
    source = write_cache(tmp_path / "cache.txt", [make_entry(md5 = "abc123")])
    database = dat.Dat()
    database.add_game(make_entry(md5 = "def456"))
    database.import_cache_dat_file(source)

    assert sorted(database.game_database) == ["abc123", "def456"]


def test_a_cache_dat_file_is_exported(tmp_path):
    database = dat.Dat()
    database.add_game(make_entry(md5 = "abc123"))
    target = str(tmp_path / "out.txt")

    assert database.export_cache_dat_file(target) is True
    with open(target, encoding = "utf8") as handle:
        assert handle.read().strip() == cache_line(make_entry(md5 = "abc123"))


def test_a_cache_dat_file_round_trips(tmp_path):
    original = dat.Dat()
    for index, name in enumerate(["Chrono Trigger", "Super Metroid", "Earthbound"]):
        original.add_game(make_entry(game = name, file = name + ".sfc", md5 = "md5%d" % index))
    target = str(tmp_path / "out.txt")
    original.export_cache_dat_file(target)

    restored = dat.Dat()
    restored.import_cache_dat_file(target)

    assert restored.game_database == original.game_database


def test_a_game_name_with_spaces_round_trips(tmp_path):
    # The separator is " || ", so ordinary spaces in a title must survive.
    original = dat.Dat()
    original.add_game(make_entry(game = "Final Fantasy VI (USA) (Rev 1)", md5 = "abc123"))
    target = str(tmp_path / "out.txt")
    original.export_cache_dat_file(target)

    restored = dat.Dat()
    restored.import_cache_dat_file(target)

    assert restored.get_by_md5("abc123")[config.dat_key_game] == "Final Fantasy VI (USA) (Rev 1)"


def test_pretending_does_not_write_a_cache_dat_file(tmp_path):
    database = dat.Dat()
    database.add_game(make_entry())
    target = tmp_path / "out.txt"

    assert database.export_cache_dat_file(str(target), pretend_run = True) is True
    assert not target.exists()


def test_pretending_does_not_import_a_cache_dat_file(tmp_path):
    source = write_cache(tmp_path / "cache.txt", [make_entry(md5 = "abc123")])
    database = dat.Dat()

    assert database.import_cache_dat_file(source, pretend_run = True) is True
    assert database.game_database == {}


###########################################################
# Clrmamepro dat files
###########################################################

CLRMAMEPRO_DOC = """<?xml version="1.0"?>
<datafile>
  <game name="Chrono Trigger (USA)">
    <rom name="Chrono Trigger (USA).sfc" size="4194304" crc="2d206bf7" md5="abc123"/>
  </game>
</datafile>
"""


def test_a_clrmamepro_dat_file_is_imported(tmp_path):
    source = write_xml(tmp_path / "roms.dat", CLRMAMEPRO_DOC)
    database = dat.Dat()

    assert database.import_clrmamepro_dat_file(source) is True
    entry = database.get_by_md5("abc123")
    assert entry[config.dat_key_game] == "Chrono Trigger (USA)"
    assert entry[config.dat_key_file] == "Chrono Trigger (USA).sfc"
    assert entry[config.dat_key_size] == "4194304"
    assert entry[config.dat_key_crc] == "2d206bf7"


def test_a_windows_rom_path_is_reduced_to_its_filename(tmp_path):
    # Dats from Windows tools carry backslash paths; only the filename is used
    # for renaming.
    source = write_xml(tmp_path / "roms.dat", """<?xml version="1.0"?>
<datafile>
  <game name="Game">
    <rom name="subdir\\\\Game.sfc" size="1" crc="0" md5="abc123"/>
  </game>
</datafile>
""")
    database = dat.Dat()
    database.import_clrmamepro_dat_file(source)

    assert database.get_by_md5("abc123")[config.dat_key_file] == "Game.sfc"


@pytest.mark.parametrize("attribute", ["size", "crc", "md5"])
def test_a_rom_missing_an_attribute_is_skipped(tmp_path, attribute):
    attributes = {"size": "1", "crc": "0", "md5": "abc123"}
    del attributes[attribute]
    rendered = " ".join('%s="%s"' % pair for pair in attributes.items())
    source = write_xml(tmp_path / "roms.dat", """<?xml version="1.0"?>
<datafile>
  <game name="Game">
    <rom name="Game.sfc" %s/>
  </game>
</datafile>
""" % rendered)
    database = dat.Dat()

    assert database.import_clrmamepro_dat_file(source) is True
    assert database.game_database == {}


def test_a_multi_disc_game_contributes_one_entry_per_rom(tmp_path):
    source = write_xml(tmp_path / "roms.dat", """<?xml version="1.0"?>
<datafile>
  <game name="Final Fantasy VII">
    <rom name="Disc 1.bin" size="1" crc="0" md5="aaa"/>
    <rom name="Disc 2.bin" size="1" crc="0" md5="bbb"/>
  </game>
</datafile>
""")
    database = dat.Dat()
    database.import_clrmamepro_dat_file(source)

    assert sorted(database.game_database) == ["aaa", "bbb"]
    assert database.get_by_md5("bbb")[config.dat_key_game] == "Final Fantasy VII"


def test_a_game_with_no_roms_contributes_nothing(tmp_path):
    source = write_xml(tmp_path / "roms.dat", """<?xml version="1.0"?>
<datafile>
  <game name="Game"/>
</datafile>
""")
    database = dat.Dat()

    assert database.import_clrmamepro_dat_file(source) is True
    assert database.game_database == {}


def test_malformed_xml_reports_failure(tmp_path):
    source = write_xml(tmp_path / "roms.dat", "<datafile><game name=")
    database = dat.Dat()

    assert database.import_clrmamepro_dat_file(source) is False


def test_a_missing_clrmamepro_dat_file_reports_failure(tmp_path):
    assert dat.Dat().import_clrmamepro_dat_file(str(tmp_path / "absent.dat")) is False


def test_pretending_does_not_import_a_clrmamepro_dat_file(tmp_path):
    source = write_xml(tmp_path / "roms.dat", CLRMAMEPRO_DOC)
    database = dat.Dat()

    assert database.import_clrmamepro_dat_file(source, pretend_run = True) is True
    assert database.game_database == {}


def test_a_directory_of_clrmamepro_dat_files_is_imported(tmp_path):
    write_xml(tmp_path / "first.dat", CLRMAMEPRO_DOC)
    write_xml(tmp_path / "second.dat", CLRMAMEPRO_DOC.replace("abc123", "def456"))
    database = dat.Dat()
    database.import_clrmamepro_dat_files(str(tmp_path))

    assert sorted(database.game_database) == ["abc123", "def456"]


def test_a_non_dat_file_in_the_directory_is_ignored(tmp_path):
    write_xml(tmp_path / "first.dat", CLRMAMEPRO_DOC)
    write_xml(tmp_path / "notes.txt", "not a dat file")
    database = dat.Dat()
    database.import_clrmamepro_dat_files(str(tmp_path))

    assert sorted(database.game_database) == ["abc123"]


def test_an_empty_dat_directory_imports_nothing(tmp_path):
    database = dat.Dat()
    database.import_clrmamepro_dat_files(str(tmp_path))

    assert database.game_database == {}


###########################################################
# Renaming
###########################################################

def test_a_matched_file_is_renamed_to_its_dat_name(tmp_path):
    rom = tmp_path / "unknown.sfc"
    rom.write_bytes(b"rom contents")

    import hashlib
    digest = hashlib.md5(b"rom contents").hexdigest()

    database = dat.Dat()
    database.add_game(make_entry(file = "Chrono Trigger (USA).sfc", md5 = digest))
    database.rename_files(str(tmp_path))

    assert (tmp_path / "Chrono Trigger (USA).sfc").exists()
    assert not rom.exists()


def test_an_unmatched_file_is_left_alone(tmp_path):
    rom = tmp_path / "unknown.sfc"
    rom.write_bytes(b"rom contents")

    database = dat.Dat()
    database.add_game(make_entry(md5 = "not-a-real-hash"))
    database.rename_files(str(tmp_path))

    assert rom.exists()


def test_a_correctly_named_file_is_not_moved(tmp_path):
    import hashlib
    digest = hashlib.md5(b"rom contents").hexdigest()

    rom = tmp_path / "Chrono Trigger (USA).sfc"
    rom.write_bytes(b"rom contents")

    database = dat.Dat()
    database.add_game(make_entry(file = "Chrono Trigger (USA).sfc", md5 = digest))
    database.rename_files(str(tmp_path))

    assert rom.read_bytes() == b"rom contents"
    assert len(list(tmp_path.iterdir())) == 1
