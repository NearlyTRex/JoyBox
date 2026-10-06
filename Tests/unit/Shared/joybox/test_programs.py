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


###########################################################
# Config lookup
#
# Program configs are nested by name, then key, then optionally platform.
# A lookup that misses returns None rather than raising, because most keys are
# declared by only some programs.
###########################################################

SAMPLE_CONFIG = {
    "SampleTool": {
        "program": {"linux": "SampleTool/linux/tool", "windows": "SampleTool\\tool.exe"},
        "config_file": "SampleTool/config.ini",
        "run_sandboxed": {"linux": False, "windows": True},
        "lib32": ["a.dll", "b.dll"],
    },
}


def test_a_platform_value_is_selected():
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "program", "linux") == \
        "SampleTool/linux/tool"


def test_another_platform_selects_its_own_value():
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "program", "windows") == \
        "SampleTool\\tool.exe"


def test_a_flat_value_is_returned_as_is():
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "config_file", "linux") == \
        "SampleTool/config.ini"


def test_a_list_value_is_returned_whole():
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "lib32", "linux") == \
        ["a.dll", "b.dll"]


def test_an_unlisted_platform_returns_the_mapping_itself():
    # Callers that understand the shape can still pick from it.
    built = programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "program", "beos")

    assert built == SAMPLE_CONFIG["SampleTool"]["program"]


def test_an_unknown_program_has_no_value():
    assert programs.get_config_value(SAMPLE_CONFIG, "Absent", "program", "linux") is None


def test_an_unknown_key_has_no_value():
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "absent", "linux") is None


def test_a_false_value_is_preserved():
    # run_sandboxed is explicitly false on native builds, which is not the
    # same as being unset.
    assert programs.get_config_value(SAMPLE_CONFIG, "SampleTool", "run_sandboxed", "linux") is False


###########################################################
# Path composition
###########################################################

def test_a_relative_path_is_placed_under_the_base():
    built = programs.get_path_config_value(
        SAMPLE_CONFIG, "/tools", "SampleTool", "config_file", "linux")

    assert built == "/tools/SampleTool/config.ini"


def test_an_absolute_existing_path_is_left_alone(tmp_path):
    target = tmp_path / "tool"
    target.write_text("x")
    config_with_absolute = {"SampleTool": {"program": str(target)}}
    built = programs.get_path_config_value(
        config_with_absolute, "/tools", "SampleTool", "program", "linux")

    assert built == str(target)


def test_a_missing_key_composes_no_path():
    assert programs.get_path_config_value(
        SAMPLE_CONFIG, "/tools", "SampleTool", "absent", "linux") is None


def test_a_program_is_the_program_key():
    built = programs.get_program(SAMPLE_CONFIG, "/tools", "SampleTool", "linux")

    assert built == "/tools/SampleTool/linux/tool"


###########################################################
# Classifying a program path
#
# These decide whether a command being run is one of JoyBox's own programs,
# which in turn decides whether it is wrapped for a prefix.
###########################################################

@pytest.fixture
def known_tool():
    for tool in programs.get_tools():
        path = programs.get_tool_program(tool.get_name())
        if path and os.path.exists(path):
            return tool.get_name(), path
    pytest.skip("no installed tool to classify")


def test_a_tool_path_is_recognised_as_a_tool(known_tool):
    # Returning the negation here made every path look like a tool, and no
    # tool look like one.
    name, path = known_tool

    assert programs.is_program_path_tool(path) is True


def test_a_tool_path_is_not_an_emulator(known_tool):
    name, path = known_tool

    assert programs.is_program_path_emulator(path) is False


def test_an_unrelated_path_is_neither():
    assert programs.is_program_path_tool("/usr/bin/ls") is False
    assert programs.is_program_path_emulator("/usr/bin/ls") is False


def test_a_missing_path_is_neither(tmp_path):
    absent = str(tmp_path / "absent")

    assert programs.is_program_path_tool(absent) is False
    assert programs.is_program_path_emulator(absent) is False


@pytest.mark.parametrize("value", [None, ""])
def test_an_empty_path_is_neither(value):
    assert programs.is_program_path_tool(value) is False
    assert programs.is_program_path_emulator(value) is False


def test_a_tool_name_is_derived_from_its_path(known_tool):
    name, path = known_tool

    assert programs.derive_tool_name_from_program_path(path) == name


def test_an_unrelated_path_derives_no_tool_name():
    assert programs.derive_tool_name_from_program_path("/usr/bin/ls") is None


def test_a_missing_path_derives_no_tool_name(tmp_path):
    assert programs.derive_tool_name_from_program_path(str(tmp_path / "absent")) is None


###########################################################
# Sandboxing
#
# run_sandboxed is declared per platform, and native linux builds set it to
# false. Asking whether the key exists is not the same as asking what it says.
###########################################################

def test_a_tool_sandboxed_on_this_platform_is_reported(monkeypatch):
    monkeypatch.setattr(
        programs, "get_tool_config_value", lambda name, key, platform = None: True)

    assert programs.is_program_name_sandboxed_tool("SampleTool") is True


def test_a_tool_not_sandboxed_on_this_platform_is_not(monkeypatch):
    monkeypatch.setattr(
        programs, "get_tool_config_value", lambda name, key, platform = None: False)

    assert programs.is_program_name_sandboxed_tool("SampleTool") is False


def test_a_tool_that_never_declares_sandboxing_is_not(monkeypatch):
    monkeypatch.setattr(
        programs, "get_tool_config_value", lambda name, key, platform = None: None)

    assert programs.is_program_name_sandboxed_tool("SampleTool") is False


def test_an_emulator_not_sandboxed_on_this_platform_is_not(monkeypatch):
    monkeypatch.setattr(
        programs, "get_emulator_config_value", lambda name, key, platform = None: False)

    assert programs.is_program_name_sandboxed_emulator("SampleEmulator") is False


def test_the_name_and_path_forms_agree(monkeypatch, known_tool):
    name, path = known_tool

    assert programs.is_program_name_sandboxed_tool(name) == \
        programs.is_program_path_sandboxed_tool(path)


def test_an_unrelated_path_is_not_a_sandboxed_program():
    assert programs.is_program_path_sandboxed_tool("/usr/bin/ls") is False
    assert programs.is_program_path_sandboxed_emulator("/usr/bin/ls") is False


###########################################################
# Install state
###########################################################

def test_an_installed_tool_is_reported_installed(known_tool):
    name, path = known_tool

    assert programs.is_tool_installed(name) is True


def test_an_unknown_tool_is_not_installed():
    assert programs.is_tool_installed("NotARealTool") is False


def test_an_unknown_emulator_is_not_installed():
    assert programs.is_emulator_installed("NotARealEmulator") is False


###########################################################
# Library directories
###########################################################

def test_a_library_install_dir_sits_under_the_tools_root(monkeypatch):
    monkeypatch.setattr(programs.environment, "get_tools_root_dir", lambda: "/tools")

    assert programs.get_library_install_dir("DXVK") == "/tools/DXVK"


def test_a_library_install_dir_can_be_platform_specific(monkeypatch):
    monkeypatch.setattr(programs.environment, "get_tools_root_dir", lambda: "/tools")

    assert programs.get_library_install_dir("DXVK", "linux") == "/tools/DXVK/linux"


def test_a_library_backup_dir_is_separate_from_its_install_dir(monkeypatch):
    monkeypatch.setattr(programs.environment, "get_tools_root_dir", lambda: "/tools")
    monkeypatch.setattr(
        programs.environment, "get_locker_program_tool_dir",
        lambda name, platform = None: "/locker/Programs/Tools/" + name)

    assert programs.get_library_install_dir("DXVK") != programs.get_library_backup_dir("DXVK")


###########################################################
# Program registry seams
###########################################################

@pytest.fixture
def fake_registry(monkeypatch, tmp_path):
    tools_root = tmp_path / "Tools"
    emulators_root = tmp_path / "Emulators"
    (tools_root / "Packer" / "linux").mkdir(parents = True)
    (tools_root / "Packer" / "linux" / "packer").write_text("")
    tool_config = {
        "Packer": {"program": {"linux": "Packer/linux/packer"}, "run_sandboxed": {"linux": "wine"}},
        "Ghost": {"program": {"linux": "Ghost/linux/ghost"}},
    }
    emulator_config = {
        "Retro": {"program": {"linux": "Retro/linux/retro"}, "run_sandboxed": {"linux": "wine"}},
    }
    monkeypatch.setattr(programs, "get_tool_config", lambda: tool_config)
    monkeypatch.setattr(programs, "get_emulator_config", lambda: emulator_config)
    monkeypatch.setattr(programs.environment, "get_tools_root_dir", lambda: str(tools_root))
    monkeypatch.setattr(programs.environment, "get_emulators_root_dir", lambda: str(emulators_root))
    monkeypatch.setattr(programs.platform_info, "get_current_platform", lambda: "linux")
    monkeypatch.setattr(programs.platform_info, "is_linux_platform", lambda: True)
    return {
        "tools_root": str(tools_root),
        "emulators_root": str(emulators_root),
        "packer": str(tools_root / "Packer" / "linux" / "packer"),
    }


def test_program_names_are_classified_by_registry(fake_registry):
    assert programs.is_program_name_tool("Packer", "linux") is True
    assert programs.is_program_name_emulator("Packer", "linux") is False
    assert programs.is_program_name_emulator("Retro", "linux") is True
    assert programs.is_program_name_tool("Retro", "linux") is False


def test_install_and_backup_dirs_follow_the_program_kind(monkeypatch, fake_registry):
    monkeypatch.setattr(
        programs.environment, "get_locker_program_tool_dir",
        lambda name, platform = None: "/locker/Tools/%s/%s" % (name, platform))
    monkeypatch.setattr(
        programs.environment, "get_locker_gaming_emulator_binaries_dir",
        lambda name, platform = None: "/locker/Emulators/%s/%s" % (name, platform))

    assert programs.get_program_install_dir("Packer", "linux") == fake_registry["tools_root"] + "/Packer/linux"
    assert programs.get_program_install_dir("Retro", "linux") == fake_registry["emulators_root"] + "/Retro/linux"
    assert programs.get_program_install_dir("Unknown", "linux") is None
    assert programs.get_program_backup_dir("Packer", "linux") == "/locker/Tools/Packer/linux"
    assert programs.get_program_backup_dir("Retro", "linux") == "/locker/Emulators/Retro/linux"
    assert programs.get_program_backup_dir("Unknown", "linux") is None


def test_a_platform_library_backup_dir_is_nested_by_platform(monkeypatch):
    monkeypatch.setattr(
        programs.environment, "get_locker_program_tool_dir", lambda name, platform = None: "/locker/" + name)

    assert programs.get_library_backup_dir("DXVK", "linux") == "/locker/DXVK/linux"


def test_a_missing_program_should_be_installed(fake_registry):
    assert programs.should_program_be_installed("Ghost") is True
    assert programs.should_program_be_installed("Retro") is True


def test_a_present_or_unknown_program_should_not_be_installed(fake_registry):
    assert programs.should_program_be_installed("Packer") is False
    assert programs.should_program_be_installed("Unknown") is False


def test_linux_programs_are_not_installed_off_linux(monkeypatch, fake_registry):
    monkeypatch.setattr(programs.platform_info, "is_linux_platform", lambda: False)

    assert programs.should_program_be_installed("Ghost", "linux") is False


def test_a_library_is_installed_when_its_directory_is_empty(fake_registry):
    assert programs.should_library_be_installed("Packer") is False
    assert programs.should_library_be_installed("Absent") is True


def test_installed_state_asks_whether_the_program_runs(monkeypatch, fake_registry):
    import joybox.command as command
    asked = []
    monkeypatch.setattr(command, "is_runnable_command", lambda path: asked.append(path) or True)

    assert programs.is_program_installed("Packer", "linux") is True
    assert programs.is_program_installed("Retro", "linux") is True
    assert programs.is_program_installed("Unknown", "linux") is False
    assert asked == [fake_registry["packer"], fake_registry["emulators_root"] + "/Retro/linux/retro"]


def test_program_dirs_are_the_program_parent(fake_registry):
    assert programs.get_tool_program_dir("Packer", "linux") == fake_registry["tools_root"] + "/Packer/linux"
    assert programs.get_emulator_program_dir("Retro", "linux") == fake_registry["emulators_root"] + "/Retro/linux"


def test_path_config_values_resolve_under_their_roots(fake_registry):
    assert programs.get_tool_path_config_value("Packer", "program", "linux") == fake_registry["packer"]
    assert programs.get_emulator_path_config_value("Retro", "program", "linux") == \
        fake_registry["emulators_root"] + "/Retro/linux/retro"


def test_emulator_install_state_checks_the_program_file(fake_registry):
    assert programs.is_emulator_installed("Retro", "linux") is False


def test_registry_paths_are_classified_and_sandboxed(fake_registry, tmp_path):
    packer = fake_registry["packer"]
    retro = tmp_path / "Emulators" / "Retro" / "linux" / "retro"
    retro.parent.mkdir(parents = True)
    retro.write_text("")

    assert programs.derive_tool_name_from_program_path(packer, "linux") == "Packer"
    assert programs.derive_emulator_name_from_program_path(str(retro), "linux") == "Retro"
    assert programs.is_program_path_sandboxed_tool(packer, "linux") == "wine"
    assert programs.is_program_path_sandboxed_emulator(str(retro), "linux") == "wine"
    assert programs.is_program_name_sandboxed_emulator("Retro", "linux") == "wine"


def test_a_registry_path_without_sandboxing_is_not_sandboxed(monkeypatch, fake_registry):
    monkeypatch.setattr(programs, "get_tool_config_value", lambda name, key, platform = None: None)
    monkeypatch.setattr(programs, "get_emulator_config_value", lambda name, key, platform = None: None)
    monkeypatch.setattr(programs, "derive_emulator_name_from_program_path", lambda path, platform = None: "Retro")

    assert programs.is_program_path_sandboxed_tool(fake_registry["packer"], "linux") is False
    assert programs.is_program_path_sandboxed_emulator("/any", "linux") is False
