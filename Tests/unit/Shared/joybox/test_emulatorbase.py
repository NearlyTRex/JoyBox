# Imports
import pytest

# Local imports
from joybox import config, emulatorbase


###########################################################
# EmulatorBase
#
# Resolves an emulator's paths out of its config dict. get_save_dir is the one
# with real branching: a per-platform sub directory when the emulator keeps
# saves in one tree, otherwise a flat save_dir.
###########################################################

ROOT = "/emulators"


@pytest.fixture
def emulator_root(monkeypatch):
    monkeypatch.setattr(
        emulatorbase.environment, "get_emulators_root_dir", lambda: ROOT)
    monkeypatch.setattr(
        emulatorbase.platform_info, "get_current_platform", lambda: "linux")
    return ROOT


def build(config_values, name = "TestMulator", platforms = None):
    class TestEmulator(emulatorbase.EmulatorBase):
        def get_name(self):
            return name

        def get_platforms(self):
            return platforms or []

        def get_config(self):
            return {name: config_values}

    return TestEmulator()


###########################################################
# Defaults
###########################################################

def test_the_base_emulator_is_anonymous():
    assert emulatorbase.EmulatorBase().get_name() == ""


def test_the_base_emulator_claims_no_platforms():
    assert emulatorbase.EmulatorBase().get_platforms() == []


def test_the_base_emulator_has_no_config():
    assert emulatorbase.EmulatorBase().get_config() == {}


def test_the_base_emulator_has_no_save_type():
    assert emulatorbase.EmulatorBase().get_save_type() is None


def test_the_base_emulator_installs_addons_successfully():
    # Most emulators have no addons; the default must not report failure.
    assert emulatorbase.EmulatorBase().install_addons() is True


###########################################################
# Path resolution
###########################################################

def test_a_config_file_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"config_file": {"linux": "TestMulator/config.ini"}})

    assert emulator.get_config_file() == "/emulators/TestMulator/config.ini"


def test_a_setup_dir_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"setup_dir": {"linux": "TestMulator/setup"}})

    assert emulator.get_setup_dir() == "/emulators/TestMulator/setup"


def test_a_missing_config_file_entry_resolves_to_nothing(emulator_root):
    assert build({}).get_config_file() is None


def test_a_requested_platform_selects_its_entry(emulator_root):
    emulator = build({"config_file": {
        "linux": "TestMulator/linux.ini",
        "windows": "TestMulator/windows.ini",
    }})

    assert emulator.get_config_file("windows") == "/emulators/TestMulator/windows.ini"


###########################################################
# Save directories
###########################################################

def test_a_flat_save_dir_is_used(emulator_root):
    emulator = build({"save_dir": {"linux": "TestMulator/saves"}})

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/saves"


def test_a_platform_sub_dir_is_appended_to_the_base(emulator_root):
    emulator = build({
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/User/NES/saves"


def test_a_sub_dir_wins_over_a_flat_save_dir(emulator_root):
    # An emulator declaring both keeps per-platform saves apart.
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/User/NES/saves"


def test_an_uncovered_platform_falls_back_to_the_flat_save_dir(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("sega_genesis") == "/emulators/TestMulator/saves"


def test_an_uncovered_platform_without_a_fallback_resolves_to_nothing(emulator_root):
    # This is what the registry sweep guards against: a silent no save dir.
    emulator = build({
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("sega_genesis") is None


def test_a_base_dir_without_sub_dirs_is_not_used_alone(emulator_root):
    # The base is a container, not a save location.
    emulator = build({"save_base_dir": {"linux": "TestMulator/User"}})

    assert emulator.get_save_dir("nintendo_nes") is None


def test_sub_dirs_without_a_base_dir_fall_back(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/saves"


def test_no_game_platform_falls_back_to_the_flat_save_dir(emulator_root):
    emulator = build({
        "save_dir": {"linux": "TestMulator/saves"},
        "save_base_dir": {"linux": "TestMulator/User"},
        "save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}},
    })

    assert emulator.get_save_dir(None) == "/emulators/TestMulator/saves"


def test_an_emulator_managing_no_saves_resolves_to_nothing(emulator_root):
    # A None save dir means JoyBox does not manage this emulator's saves.
    assert build({}).get_save_dir("nintendo_nes") is None


def test_the_emulator_platform_selects_the_sub_dir_table(emulator_root):
    emulator = build({
        "save_base_dir": {
            "linux": "TestMulator/linux",
            "windows": "TestMulator/windows",
        },
        "save_sub_dirs": {
            "linux": {"nintendo_nes": "NES/saves"},
            "windows": {"nintendo_nes": "NES\\saves"},
        },
    })

    assert emulator.get_save_dir("nintendo_nes", "windows").startswith(
        "/emulators/TestMulator/windows")


def test_the_current_platform_is_used_when_none_is_given(monkeypatch, emulator_root):
    monkeypatch.setattr(
        emulatorbase.platform_info, "get_current_platform", lambda: "windows")
    emulator = build({"save_dir": {
        "linux": "TestMulator/linux-saves",
        "windows": "TestMulator/windows-saves",
    }})

    assert emulator.get_save_dir("nintendo_nes") == "/emulators/TestMulator/windows-saves"


def test_save_sub_dirs_are_read_as_a_mapping(emulator_root):
    emulator = build({"save_sub_dirs": {"linux": {"nintendo_nes": "NES/saves"}}})

    assert emulator.get_save_sub_dirs() == {"nintendo_nes": "NES/saves"}


def test_a_missing_sub_dir_table_reads_as_nothing(emulator_root):
    assert build({}).get_save_sub_dirs() is None


def test_a_save_base_dir_is_resolved_under_the_emulator_root(emulator_root):
    emulator = build({"save_base_dir": {"linux": "TestMulator/User"}})

    assert emulator.get_save_base_dir() == "/emulators/TestMulator/User"
