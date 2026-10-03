# Imports
import pytest

# Local imports
from joybox import config, environment
from environment_helpers import LOCKER, CACHE, CATEGORY, SUBCATEGORY, SUPERCATEGORY, GAME, parts, name_path


###########################################################
# Cache
###########################################################

def test_the_gaming_cache_sits_under_the_cache(roots):
    assert environment.get_cache_gaming_root_dir().startswith(CACHE)


@pytest.mark.parametrize("accessor,supercategory", [
    ("get_cache_gaming_roms_root_dir", config.Supercategory.ROMS),
    ("get_cache_gaming_installs_root_dir", config.Supercategory.INSTALLS),
    ("get_cache_gaming_saves_root_dir", config.Supercategory.SAVES),
    ("get_cache_gaming_setup_root_dir", config.Supercategory.SETUP),
])
def test_each_cache_area_has_its_own_root(roots, accessor, supercategory):
    assert parts(getattr(environment, accessor)())[-1] == str(supercategory)


def test_the_cache_areas_are_all_distinct(roots):
    built = [environment.get_cache_gaming_rom_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_install_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME),
             environment.get_cache_gaming_setup_dir(CATEGORY, SUBCATEGORY, GAME)]

    assert len(set(built)) == len(built)


def test_a_cache_save_dir_can_be_split_by_save_type(roots):
    plain = environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME)
    typed = environment.get_cache_gaming_save_dir(
        CATEGORY, SUBCATEGORY, GAME, save_type = "memcard")

    assert typed.startswith(plain)
    assert typed.endswith("memcard")


def test_a_cache_save_dir_without_a_type_has_no_extra_level(roots):
    built = environment.get_cache_gaming_save_dir(CATEGORY, SUBCATEGORY, GAME)

    assert parts(built)[-1] == GAME
    assert parts(built)[-2] == str(SUBCATEGORY)


def test_the_cache_install_dir_uses_the_derived_name_path(roots):
    built = environment.get_cache_gaming_install_dir(CATEGORY, SUBCATEGORY, GAME)

    assert built.replace("\\", "/").endswith(name_path().replace("\\", "/"))


def test_two_games_do_not_share_a_cache_directory(roots):
    first = environment.get_cache_gaming_rom_dir(
        CATEGORY, SUBCATEGORY, "Chrono Trigger (USA)")
    second = environment.get_cache_gaming_rom_dir(
        CATEGORY, SUBCATEGORY, "Super Metroid (USA)")

    assert first != second


def test_the_cache_and_the_locker_are_separate_trees(roots):
    cache = environment.get_cache_gaming_rom_dir(CATEGORY, SUBCATEGORY, GAME)
    locker = environment.get_locker_gaming_files_dir(
        SUPERCATEGORY, CATEGORY, SUBCATEGORY, GAME)

    assert not cache.startswith(LOCKER)
    assert not locker.startswith(CACHE)
