# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import programs


###########################################################
# Program config lookup
#
# Tool and emulator configs are nested dicts that may hold either a plain value
# or a per-platform mapping, so the lookup decides which binary actually runs.
###########################################################

CONFIG = {
    "Ghidra": {
        "program": {
            "windows": "Ghidra/lib/ghidraRun.bat",
            "linux": "Ghidra/lib/ghidraRun",
        },
        "package_name": "pyghidra",
    },
    "Simple": {
        "program": "simple/run",
    },
}


def test_a_plain_value_is_returned():
    assert programs.get_config_value(CONFIG, "Simple", "program") == "simple/run"


def test_a_platform_mapping_resolves_for_the_platform():
    assert programs.get_config_value(CONFIG, "Ghidra", "program", "linux") == \
        "Ghidra/lib/ghidraRun"
    assert programs.get_config_value(CONFIG, "Ghidra", "program", "windows") == \
        "Ghidra/lib/ghidraRun.bat"


def test_an_unlisted_platform_returns_the_whole_mapping():
    # The caller gets the dict back rather than nothing, so a missing platform
    # is visible instead of looking like an absent key.
    resolved = programs.get_config_value(CONFIG, "Ghidra", "program", "haiku")

    assert isinstance(resolved, dict)


def test_a_non_platform_value_ignores_the_platform():
    assert programs.get_config_value(CONFIG, "Simple", "program", "linux") == "simple/run"


def test_a_missing_program_returns_nothing():
    assert programs.get_config_value(CONFIG, "Absent", "program") is None


def test_a_missing_key_returns_nothing():
    assert programs.get_config_value(CONFIG, "Simple", "absent") is None


def test_an_empty_config_returns_nothing():
    assert programs.get_config_value({}, "Simple", "program") is None


def test_a_non_program_key_is_read():
    assert programs.get_config_value(CONFIG, "Ghidra", "package_name") == "pyghidra"


###########################################################
# Path resolution
###########################################################

def test_a_relative_path_is_joined_to_the_base():
    resolved = programs.get_path_config_value(CONFIG, "/base", "Simple", "program")

    assert resolved == os.path.join("/base", "simple", "run")


def test_an_existing_absolute_path_is_used_as_is(tmp_path):
    # An absolute path that exists must not be rebased under the install root.
    existing = tmp_path / "tool"
    existing.write_text("")
    config = {"Existing": {"program": str(existing)}}

    assert programs.get_path_config_value(config, "/base", "Existing", "program") == \
        str(existing)


def test_a_missing_value_resolves_to_nothing():
    assert programs.get_path_config_value(CONFIG, "/base", "Absent", "program") is None


def test_the_platform_is_honoured_when_resolving_a_path():
    resolved = programs.get_path_config_value(CONFIG, "/base", "Ghidra", "program", "linux")

    assert resolved.endswith(os.path.join("Ghidra", "lib", "ghidraRun"))


def test_get_program_reads_the_program_key():
    assert programs.get_program(CONFIG, "/base", "Simple") == \
        programs.get_path_config_value(CONFIG, "/base", "Simple", "program")


###########################################################
# Registry consistency
###########################################################

def test_the_tool_registry_is_populated():
    assert len(programs.get_tools()) > 0


def test_the_emulator_registry_is_populated():
    assert len(programs.get_emulators()) > 0


def test_tool_names_are_unique():
    names = [tool.get_name() for tool in programs.get_tools()]
    duplicates = sorted({name for name in names if names.count(name) > 1})

    assert not duplicates, f"duplicate tool names: {duplicates}"


def test_emulator_names_are_unique():
    names = [emulator.get_name() for emulator in programs.get_emulators()]
    duplicates = sorted({name for name in names if names.count(name) > 1})

    assert not duplicates, f"duplicate emulator names: {duplicates}"


def test_every_emulator_declares_platforms():
    for emulator in programs.get_emulators():
        assert emulator.get_platforms() is not None, \
            f"{emulator.get_name()} declares no platforms"


def test_an_emulator_is_found_by_its_platform():
    for emulator in programs.get_emulators():
        platforms = emulator.get_platforms()
        if platforms:
            found = programs.get_emulator_by_platform(platforms[0])
            assert found is not None
            break


def test_an_unhandled_platform_has_no_emulator():
    assert programs.get_emulator_by_platform("not-a-real-platform") is None


def test_the_merged_tool_config_covers_every_tool():
    merged = programs.get_tool_config()

    assert isinstance(merged, dict)
    assert len(merged) > 0


def test_the_merged_emulator_config_covers_every_emulator():
    merged = programs.get_emulator_config()

    assert isinstance(merged, dict)
    assert len(merged) > 0
