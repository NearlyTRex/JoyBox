# Third-party imports
import pytest

# Local imports
from joybox import gameinfo


@pytest.fixture
def game(game_tree):
    from gameinfo_helpers import write_game
    return gameinfo.GameInfo(json_file = write_game(game_tree))
