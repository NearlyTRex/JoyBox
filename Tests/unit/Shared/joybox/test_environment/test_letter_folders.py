# Imports
import pytest

# Local imports
from joybox import environment, gamenaming
from environment_helpers import LOCKER, CACHE, CATEGORY, SUBCATEGORY, SUPERCATEGORY, GAME, LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_PLATFORM, LETTER_GAME, letter_platform, parts


###########################################################
# Letter folders
#
# Computer platforms bucket games under a first-letter folder; console
# platforms do not. Which of the two a path uses decides whether the rest of
# the code finds the directory at all.
###########################################################

@letter_platform
def test_a_letter_platform_buckets_by_first_letter():
    derived = gamenaming.derive_game_name_path_from_name(LETTER_GAME, LETTER_PLATFORM)

    assert derived.replace("\\", "/") == "H/Half-Life"


@letter_platform
def test_a_console_platform_does_not_bucket():
    platform = gamenaming.derive_game_platform_from_categories(CATEGORY, SUBCATEGORY)

    assert gamenaming.derive_game_name_path_from_name(GAME, platform) == GAME


@letter_platform
def test_the_locker_buckets_a_letter_platform_game(roots):
    built = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
def test_the_install_cache_buckets_a_letter_platform_game(roots):
    built = environment.get_cache_gaming_install_dir(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_every_cache_buckets_a_letter_platform_game(roots, accessor):
    # A game installed somewhere unbucketed would not be found by the code
    # that stored it bucketed.
    built = getattr(environment, accessor)(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert parts(built)[-2:] == ["H", LETTER_GAME]


@letter_platform
@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_every_cache_sits_at_the_same_depth(roots, accessor):
    built = getattr(environment, accessor)(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)
    locker = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME)

    assert len(parts(built)) - len(parts(CACHE)) == \
        len(parts(locker)) - len(parts(LOCKER))


@letter_platform
def test_a_typed_save_cache_keeps_its_bucket(roots):
    built = environment.get_cache_gaming_save_dir(
        LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_GAME, save_type = "wine")

    assert parts(built)[-3:] == ["H", LETTER_GAME, "wine"]


@pytest.mark.parametrize("accessor", [
    "get_cache_gaming_rom_dir",
    "get_cache_gaming_install_dir",
    "get_cache_gaming_save_dir",
    "get_cache_gaming_setup_dir",
])
def test_a_console_game_is_never_bucketed(roots, accessor):
    built = getattr(environment, accessor)(CATEGORY, SUBCATEGORY, GAME)

    assert parts(built)[-2:] == [str(SUBCATEGORY), GAME]
