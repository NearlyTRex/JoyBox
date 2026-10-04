# Imports
import pytest

# Local imports
from joybox import config
from joybox import emulators
from joybox import environment


###########################################################
# Pretend configure
#
# A pretend run reads and writes nothing, so every emulator that verifies
# locker system files must still report success instead of a hash mismatch.
###########################################################

VERIFYING_EMULATORS = [
    "Ares", "BasiliskII", "Citra", "Dolphin", "DuckStation", "EKA2L1", "FS-UAE",
    "Mame", "Mednafen", "melonDS", "mGBA", "PCSX2", "RetroArch", "RPCS3",
    "Vita3K", "Xemu", "Yuzu",
]


@pytest.mark.parametrize("name", VERIFYING_EMULATORS)
def test_a_pretend_configure_succeeds_and_writes_nothing(name, tmp_path, monkeypatch):
    monkeypatch.setattr(environment, "get_emulators_root_dir", lambda: str(tmp_path / "emulators"))
    monkeypatch.setattr(environment, "get_locker_gaming_emulator_setup_dir",
        lambda emulator_name: str(tmp_path / "locker" / emulator_name))
    emulator = emulators.get_emulator_by_name(name)

    assert emulator.configure(config.SetupParams(pretend_run = True)) is True
    assert list(tmp_path.iterdir()) == []
