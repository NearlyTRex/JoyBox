# Imports
import pytest

# Local imports
from joybox.collection import saves


###########################################################
# Importing a local save
#
# Launching stops when the import reports failure, so a save that unpacks
# cleanly has to say so.
###########################################################

@pytest.mark.parametrize("unpacked", [True, False])
def test_importing_a_save_reports_the_unpack_result(monkeypatch, unpacked):
    monkeypatch.setattr(saves, "can_save_be_unpacked", lambda game_info: True)
    monkeypatch.setattr(saves, "unpack_save", lambda **kwargs: unpacked)

    assert saves.import_local_game_save(game_info = object()) is unpacked


def test_a_game_without_a_packed_save_imports_nothing(monkeypatch):
    monkeypatch.setattr(saves, "can_save_be_unpacked", lambda game_info: False)
    monkeypatch.setattr(saves, "unpack_save", lambda **kwargs: pytest.fail("nothing to unpack"))

    assert saves.import_local_game_save(game_info = object()) is True
