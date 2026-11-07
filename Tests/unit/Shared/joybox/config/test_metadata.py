# Third-party imports
import pytest

# Local imports
from joybox import config


###########################################################
# Metadata source platform maps
###########################################################

# Platforms GameFAQs lists that TheGamesDB has no platform for
TGDB_UNLISTED = {
    config.Platform.NINTENDO_AMIIBO,
    config.Platform.NINTENDO_GAME_BOY_ADVANCE_EREADER,
}


@pytest.mark.parametrize("platform_map", [config.gamefaqs_platforms, config.tgdb_platforms], ids = ["gamefaqs", "tgdb"])
def test_every_mapped_platform_is_a_real_platform(platform_map):
    assert set(platform_map) <= set(config.Platform.members())


def test_tgdb_covers_every_gamefaqs_platform_it_has_an_id_for():
    assert set(config.gamefaqs_platforms) - set(config.tgdb_platforms) == TGDB_UNLISTED


@pytest.mark.parametrize("platform_ids", list(config.tgdb_platforms.values()))
def test_tgdb_platform_ids_are_non_empty_tuples_of_numeric_strings(platform_ids):
    assert isinstance(platform_ids, tuple) and platform_ids
    assert all(isinstance(platform_id, str) and platform_id.isdigit() for platform_id in platform_ids)
