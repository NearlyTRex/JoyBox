# Imports
import pytest

# Local imports
from joybox import config, programs


###########################################################
# Tool and emulator registries
#
# Both are assembled by hand in their package __init__, so an entry can be
# added to the tree and never registered - or registered twice and shadow
# another.
###########################################################

TOOLS = list(programs.get_tools())
EMULATORS = list(programs.get_emulators())

TOOL_IDS = [tool.get_name() for tool in TOOLS]
EMULATOR_IDS = [emulator.get_name() for emulator in EMULATORS]


def test_the_tool_registry_is_populated():
    assert len(TOOLS) > 50


def test_the_emulator_registry_is_populated():
    assert len(EMULATORS) > 30


###########################################################
# Identity
###########################################################

@pytest.mark.parametrize("tool", TOOLS, ids = TOOL_IDS)
def test_every_tool_has_a_name(tool):
    assert tool.get_name() and tool.get_name().strip()


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_every_emulator_has_a_name(emulator):
    assert emulator.get_name() and emulator.get_name().strip()


def test_tool_names_are_unique():
    names = [tool.get_name() for tool in TOOLS]
    duplicates = sorted({name for name in names if names.count(name) > 1})

    assert not duplicates, f"duplicate tool names: {duplicates}"


def test_emulator_names_are_unique():
    names = [emulator.get_name() for emulator in EMULATORS]
    duplicates = sorted({name for name in names if names.count(name) > 1})

    assert not duplicates, f"duplicate emulator names: {duplicates}"


def test_a_tool_and_an_emulator_do_not_share_a_name():
    # get_program dispatches on which registry a name is in, so a shared name
    # would resolve to whichever is checked first.
    shared = {tool.get_name() for tool in TOOLS} & {e.get_name() for e in EMULATORS}

    assert not shared, f"names in both registries: {sorted(shared)}"


###########################################################
# Configuration
###########################################################

@pytest.mark.parametrize("tool", TOOLS, ids = TOOL_IDS)
def test_every_tool_config_is_a_mapping(tool):
    assert isinstance(tool.get_config(), dict)


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_every_emulator_config_is_a_mapping(emulator):
    assert isinstance(emulator.get_config(), dict)


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_every_emulator_declares_a_config(emulator):
    # An emulator with no config has no program path to launch.
    assert emulator.get_config(), f"{emulator.get_name()} has an empty config"


def test_merged_configs_do_not_lose_entries():
    # get_tool_config merges every tool's config into one dict, so two tools
    # declaring the same key would silently drop one.
    declared = []
    for tool in TOOLS:
        declared += list(tool.get_config().keys())
    duplicates = sorted({key for key in declared if declared.count(key) > 1})

    assert not duplicates, f"tool config keys declared more than once: {duplicates}"


def test_merged_emulator_configs_do_not_lose_entries():
    declared = []
    for emulator in EMULATORS:
        declared += list(emulator.get_config().keys())
    duplicates = sorted({key for key in declared if declared.count(key) > 1})

    assert not duplicates, f"emulator config keys declared more than once: {duplicates}"


###########################################################
# Platform coverage
###########################################################

@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_every_declared_platform_is_registered(emulator):
    # A platform string that is not a real member never matches anything, so
    # the emulator is silently unreachable for it.
    for platform in emulator.get_platforms() or []:
        assert platform in config.Platform.members(), \
            f"{emulator.get_name()} claims unknown platform {platform!r}"


def test_no_platform_is_claimed_by_two_emulators():
    # get_emulator_by_platform returns the first match, so a second claim on
    # the same platform is unreachable.
    claimed = {}
    for emulator in EMULATORS:
        for platform in emulator.get_platforms() or []:
            claimed.setdefault(str(platform), []).append(emulator.get_name())

    conflicts = {name: owners for name, owners in claimed.items() if len(owners) > 1}
    assert not conflicts, f"platforms claimed more than once: {conflicts}"


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_a_declared_platform_resolves_back_to_its_emulator(emulator):
    for platform in emulator.get_platforms() or []:
        found = programs.get_emulator_by_platform(platform)
        assert found is not None
        assert found.get_name() == emulator.get_name()


def test_an_unknown_platform_resolves_to_nothing():
    assert programs.get_emulator_by_platform("not-a-real-platform") is None


def test_launchable_platforms_have_an_emulator():
    # A platform launched by file with no emulator cannot be played at all.
    from joybox import platforms as platform_helpers

    covered = set()
    for emulator in EMULATORS:
        covered.update(emulator.get_platforms() or [])

    uncovered = sorted(
        str(platform) for platform in config.Platform.members()
        if platform not in covered and platform_helpers.is_launched_by_file(platform))

    assert uncovered == [], f"launchable platforms with no emulator: {uncovered}"


###########################################################
# Save directories
#
# get_save_dir falls back to the "save_dir" key when a platform has no
# save_sub_dirs entry, and a None result means JoyBox does not manage saves
# for that emulator at all. Both are deliberate; a mix inside one emulator
# that has no fallback is not.
###########################################################

def emulator_save_config(emulator):
    return emulator.get_config().get(emulator.get_name(), {})


def has_save_fallback(emulator):
    save_dir = emulator_save_config(emulator).get("save_dir")
    if not isinstance(save_dir, dict):
        return bool(save_dir)
    return all(value is not None for value in save_dir.values())


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_save_coverage_is_all_or_nothing(emulator):
    # Without a fallback, an uncovered platform silently resolves to no save
    # directory while its siblings resolve correctly.
    if has_save_fallback(emulator):
        pytest.skip(f"{emulator.get_name()} has a save_dir fallback")

    sub_dirs = emulator_save_config(emulator).get("save_sub_dirs") or {}
    claimed = emulator.get_platforms() or []
    if not claimed or not sub_dirs:
        pytest.skip(f"{emulator.get_name()} does not manage saves")

    uncovered = [str(platform) for platform in claimed if platform not in sub_dirs]

    assert not uncovered, \
        f"{emulator.get_name()} manages saves for some platforms but not {uncovered}"


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_save_directories_are_only_declared_for_claimed_platforms(emulator):
    # A sub dir for a platform the emulator does not claim is unreachable.
    sub_dirs = emulator_save_config(emulator).get("save_sub_dirs") or {}
    claimed = set(emulator.get_platforms() or [])

    stray = [
        str(platform) for platform in sub_dirs
        if platform in config.Platform.members() and platform not in claimed
    ]

    assert not stray, f"{emulator.get_name()} declares save dirs for unclaimed {stray}"


@pytest.mark.parametrize("emulator", EMULATORS, ids = EMULATOR_IDS)
def test_core_mappings_only_name_claimed_platforms(emulator):
    # A core mapped for an unclaimed platform never runs.
    cores = emulator_save_config(emulator).get("cores_mapping") or {}
    claimed = set(emulator.get_platforms() or [])

    stray = [
        str(platform) for platform in cores
        if platform in config.Platform.members() and platform not in claimed
    ]

    assert not stray, f"{emulator.get_name()} maps cores for unclaimed {stray}"
