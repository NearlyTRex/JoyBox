# Imports
import getpass
import string
import sys

# Third-party imports
import pytest

# Local imports
from joybox.config import general

TOKEN_NAMES = sorted(name for name, value in vars(general).items() if name.startswith("token_") and isinstance(value, str))
ROOT_TOKEN_NAMES = [name for name in TOKEN_NAMES if name not in ("token_command_split", "token_glob")]
DISC_TOKEN_NAMES = [name for name in TOKEN_NAMES if name.startswith("token_disc_")]
MIME_LISTS = sorted(name for name in vars(general) if name.startswith("mime_types_"))
REPLACEMENT_TABLES = ["rich_text_replacements", "web_text_replacements", "path_text_replacements"]


###########################################################
# Python version
###########################################################

def test_minimum_python_version_is_built_from_its_parts():
    assert general.minimum_python_version == (
        general.minimum_python_major_version,
        general.minimum_python_minor_version,
        general.minimum_python_patch_version)


def test_running_interpreter_meets_the_minimum():
    assert tuple(sys.version_info[:3]) >= general.minimum_python_version


###########################################################
# Tokens
###########################################################

@pytest.mark.parametrize("name", ROOT_TOKEN_NAMES)
def test_token_value_is_its_upper_cased_name(name):
    assert getattr(general, name) == name.removeprefix("token_").upper()


def test_token_values_are_unique():
    values = [getattr(general, name) for name in TOKEN_NAMES]
    assert len(values) == len(set(values))


def test_disc_token_list_holds_every_disc_token():
    assert sorted(general.tokens_disc) == sorted(getattr(general, name) for name in DISC_TOKEN_NAMES)
    assert general.tokens_disc[0] == general.token_disc_main_root


def test_disc_names_cover_every_disc_token_but_the_main_root():
    assert set(general.token_disc_names) == set(general.tokens_disc) - {general.token_disc_main_root}


def test_disc_names_are_unique():
    assert len(set(general.token_disc_names.values())) == len(general.token_disc_names)


@pytest.mark.parametrize("disc_name", list(general.token_disc_names.values()))
def test_no_disc_name_contains_another(disc_name):
    # Disc names are matched by substring against file names, first hit wins
    assert [other for other in general.token_disc_names.values() if other != disc_name and disc_name in other] == []


def test_command_split_token_cannot_appear_in_a_path():
    assert not set(general.token_command_split) & set(string.ascii_letters + string.digits + "/\\. ")


###########################################################
# Drives
###########################################################

def test_regular_drives_run_from_start_up_to_but_excluding_end():
    assert general.drives_regular[0] == general.drive_available_start
    assert chr(ord(general.drives_regular[-1]) + 1) == general.drive_available_end
    assert general.drives_regular == sorted(general.drives_regular)


def test_regular_and_special_drives_are_disjoint_single_letters():
    letters = general.drives_regular + general.drives_special
    assert len(letters) == len(set(letters))
    assert all(len(letter) == 1 and letter in string.ascii_lowercase for letter in letters)


def test_there_is_a_regular_drive_for_every_disc_token():
    assert len(general.drives_regular) >= len(general.tokens_disc)


###########################################################
# Folders
###########################################################

def test_user_folders_hold_every_computer_folder_but_dos_and_scumm():
    folder_names = {name for name in vars(general) if name.startswith("computer_folder_")}
    expected = {getattr(general, name) for name in folder_names - {"computer_folder_dos", "computer_folder_scumm"}}
    assert set(general.computer_user_folders) == expected
    assert len(general.computer_user_folders) == len(expected)


###########################################################
# Sizes
###########################################################

def test_byte_units_scale_by_1024():
    assert general.bytes_per_megabyte == general.bytes_per_kilobyte * 1024
    assert general.bytes_per_gigabyte == general.bytes_per_megabyte * 1024


@pytest.mark.parametrize("limit, capacity_gb", [
    (general.max_disc_data_size_25gb, 25),
    (general.max_disc_data_size_50gb, 50),
    (general.max_disc_data_size_100gb, 100)
], ids = ["25gb", "50gb", "100gb"])
def test_disc_data_limits_leave_headroom_below_capacity(limit, capacity_gb):
    assert 0 < limit < capacity_gb * 1000 * 1000 * 1000


def test_chunk_sizes_are_whole_kilobytes():
    assert general.hash_chunk_size % general.bytes_per_kilobyte == 0
    assert general.transfer_chunk_size % general.bytes_per_kilobyte == 0
    assert general.transfer_chunk_size > 0


def test_boxfront_dimensions_are_built_from_its_parts():
    assert general.asset_boxfront_dimensions == (general.asset_boxfront_width, general.asset_boxfront_height)


###########################################################
# Mime types and registry
###########################################################

@pytest.mark.parametrize("name", MIME_LISTS)
def test_mime_types_are_application_types(name):
    assert all(mime.startswith("application/") for mime in getattr(general, name))


def test_mime_types_are_not_shared_between_lists():
    mimes = [mime for name in MIME_LISTS for mime in getattr(general, name)]
    assert len(mimes) == len(set(mimes))


@pytest.mark.parametrize("export_keys, ignored_keys", [
    (general.registry_export_keys_setup, general.ignored_registry_keys_setup),
    (general.registry_export_keys_game, general.ignored_registry_keys_game)
], ids = ["setup", "game"])
def test_ignored_registry_keys_sit_under_an_exported_key(export_keys, ignored_keys):
    long_exports = [key.replace("HKCU", "HKEY_CURRENT_USER").replace("HKLM", "HKEY_LOCAL_MACHINE").lower() for key in export_keys]
    assert all(any(ignored.lower().startswith(export + "\\") for export in long_exports) for ignored in ignored_keys)


def test_registry_filenames_are_distinct_reg_files():
    filenames = [general.registry_filename_setup, general.registry_filename_game, general.registry_filename_user]
    assert len(set(filenames)) == 3
    assert all(filename.endswith(".reg") for filename in filenames)


###########################################################
# Paths and text
###########################################################

def test_ignored_install_paths_include_the_current_user():
    assert getpass.getuser() in general.ignored_paths_install
    assert len(general.ignored_paths_install) == len(set(general.ignored_paths_install))


@pytest.mark.parametrize("base", list(general.appdata_variants))
def test_appdata_variants_are_slash_wrapped_and_distinct_from_their_base(base):
    variants = general.appdata_variants[base]
    assert all(path.startswith("/") and path.endswith("/") for path in [base] + variants)
    assert base not in variants


def test_flippable_words_are_unique_capitalised_words():
    assert len(general.flippable_words) == len(set(general.flippable_words))
    assert all(word == word.capitalize() and " " not in word for word in general.flippable_words)


def test_filler_words_are_unique_and_lower_case():
    assert len(general.filler_words) == len(set(general.filler_words))
    assert all(word == word.lower() for word in general.filler_words)


@pytest.mark.parametrize("table", REPLACEMENT_TABLES)
def test_replacements_do_not_feed_each_other(table):
    replacements = getattr(general, table)
    assert all(old and old != new for old, new in replacements.items())
    assert [new for new in replacements.values() if new in replacements] == []


def test_path_replacements_strip_every_character_illegal_on_windows():
    assert set('<>:"/\\|?*') == set(general.path_text_replacements)
    assert set(general.path_text_replacements.values()) == {""}


def test_rich_text_replacements_produce_ascii():
    assert all(new.isascii() for new in general.rich_text_replacements.values())
