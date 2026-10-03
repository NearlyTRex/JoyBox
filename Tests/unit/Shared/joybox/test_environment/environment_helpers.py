# Imports
import pytest

# Local imports
from joybox import config, gamenaming


###########################################################
# Shared values for the environment suite
###########################################################

LOCKER = "/locker"
CACHE = "/cache"
METADATA = "/metadata"

CATEGORY = config.Category.NINTENDO
SUBCATEGORY = config.Subcategory.NINTENDO_NES
SUPERCATEGORY = config.Supercategory.ROMS
GAME = "Chrono Trigger (USA)"

LOCKER_ROOT = "/tmp/joybox-test-locker"
GENRE = config.AudioGenreType.members()[0]


def parts(path):
    return path.replace("\\", "/").strip("/").split("/")


def name_path():
    platform = gamenaming.derive_game_platform_from_categories(CATEGORY, SUBCATEGORY)
    return gamenaming.derive_game_name_path_from_name(GAME, platform)


def letter_categories():
    from joybox import platforms as platform_helpers

    for platform in config.Platform.members():
        if not platform_helpers.is_letter_platform(platform):
            continue
        for subcategory in config.Subcategory.members():
            if platform.val().endswith(subcategory.val()):
                return config.Category.COMPUTER, subcategory, platform
    return None, None, None


LETTER_CATEGORY, LETTER_SUBCATEGORY, LETTER_PLATFORM = letter_categories()
LETTER_GAME = "Half-Life"

letter_platform = pytest.mark.skipif(
    LETTER_SUBCATEGORY is None, reason = "no letter platform is registered")
