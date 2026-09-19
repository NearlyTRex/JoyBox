# Imports
import pytest

# Local imports
from joybox import manifest


###########################################################
# Manifest entries
#
# Ludusavi manifest data augments what a store knows about a game's save
# paths and registry keys, so a lookup that silently finds nothing leaves
# saves unbacked.
###########################################################

WINDOWS_ENTRY = {
    "files": {
        "<base>/save": {"when": [{"os": "windows"}]},
        "<base>/linuxonly": {"when": [{"os": "linux"}]},
        "<base>/steamonly": {"when": [{"store": "steam"}]},
        "<base>/dos": {"when": [{"os": "dos"}]},
    },
    "registry": {
        "HKEY_CURRENT_USER/Software/Game": {},
        "HKEY_CURRENT_USER/Software/Other": {},
    },
    "installDir": {"Chrono Trigger": {}},
    "steam": {"id": 12345},
    "gog": {"id": 67890},
}


def build(data = None):
    return manifest.ManifestEntry(data if data is not None else WINDOWS_ENTRY)


###########################################################
# Paths
###########################################################

def test_windows_paths_are_collected():
    paths = build().get_paths("/base")

    assert any("save" in path for path in paths)


def test_dos_paths_are_collected():
    # DOS games are launched through the same Windows-side tooling.
    paths = build().get_paths("/base")

    assert any("dos" in path for path in paths)


def test_steam_paths_without_an_os_are_collected():
    paths = build().get_paths("/base")

    assert any("steamonly" in path for path in paths)


def test_linux_only_paths_are_skipped():
    paths = build().get_paths("/base")

    assert not any("linuxonly" in path for path in paths)


def test_an_entry_without_files_has_no_paths():
    assert build({}).get_paths("/base") == []


def test_an_entry_without_when_conditions_has_no_paths():
    # A file with no "when" block cannot be attributed to a platform.
    entry = build({"files": {"<base>/save": {}}})

    assert entry.get_paths("/base") == []


###########################################################
# Registry keys
###########################################################

def test_registry_keys_are_collected():
    keys = build().get_keys()

    assert len(keys) == 2
    assert "HKEY_CURRENT_USER/Software/Game" in keys


def test_an_entry_without_registry_has_no_keys():
    assert build({}).get_keys() == []


###########################################################
# Install directory
###########################################################

def test_the_install_directory_is_the_mapping_key():
    # installDir maps a name to its details; iterating it yields the names.
    assert build().get_install_dir() == "Chrono Trigger"


@pytest.mark.parametrize("name", ["AB", "A", "A Very Long Directory Name"])
def test_any_length_of_directory_name_works(name):
    assert build({"installDir": {name: {}}}).get_install_dir() == name


def test_an_entry_without_an_install_directory_has_none():
    assert build({}).get_install_dir() is None


def test_an_empty_install_directory_mapping_has_none():
    assert build({"installDir": {}}).get_install_dir() is None


###########################################################
# Lookups
###########################################################

@pytest.fixture
def loaded_manifest():
    return manifest.Manifest({
        "Chrono Trigger": WINDOWS_ENTRY,
        "Other Game": {"steam": {"id": 999}, "gog": {"id": 888}},
    })


def test_an_entry_is_found_by_exact_name(loaded_manifest):
    found = loaded_manifest.find_entry_by_name("Chrono Trigger")

    assert found is not None
    assert found.get_install_dir() == "Chrono Trigger"


def test_an_entry_is_found_by_a_close_name(loaded_manifest):
    # Names come from store metadata and rarely match exactly.
    assert loaded_manifest.find_entry_by_name("Chrono Trigger ") is not None


def test_an_unrelated_name_finds_nothing(loaded_manifest):
    assert loaded_manifest.find_entry_by_name("Completely Different") is None


def test_an_entry_is_found_by_steam_id(loaded_manifest):
    found = loaded_manifest.find_entry_by_steamid(12345)

    assert found is not None
    assert found.get_install_dir() == "Chrono Trigger"


def test_a_steam_id_matches_as_a_string(loaded_manifest):
    assert loaded_manifest.find_entry_by_steamid("12345") is not None


def test_an_unknown_steam_id_finds_nothing(loaded_manifest):
    assert loaded_manifest.find_entry_by_steamid(1) is None


def test_an_entry_is_found_by_gog_id(loaded_manifest):
    assert loaded_manifest.find_entry_by_gogid(67890) is not None


def test_an_unknown_gog_id_finds_nothing(loaded_manifest):
    assert loaded_manifest.find_entry_by_gogid(1) is None


def test_an_entry_without_the_store_is_skipped():
    # Missing store blocks must be skipped rather than raising.
    loaded = manifest.Manifest({"No Stores": {"files": {}}})

    assert loaded.find_entry_by_steamid(1) is None
    assert loaded.find_entry_by_gogid(1) is None


def test_an_empty_manifest_finds_nothing():
    empty = manifest.Manifest()

    assert empty.find_entry_by_name("anything") is None
    assert empty.find_entry_by_steamid(1) is None


###########################################################
# Shared instance
###########################################################

def test_the_shared_instance_is_reused():
    assert manifest.get_manifest_instance() is manifest.get_manifest_instance()
