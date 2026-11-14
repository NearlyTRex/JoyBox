# Third-party imports
import pytest

# Local imports
from joybox.config import decompiler

PRESETS = list(decompiler.decompiler_presets.items())
PRESET_IDS = [name for name, _ in PRESETS]
SCRIPTS = [
    (preset_name, script_name, script)
    for preset_name, preset in PRESETS
    for script_name, script in preset["scripts"].items()
]
SCRIPT_IDS = ["%s-%s" % (preset_name, script_name) for preset_name, script_name, _ in SCRIPTS]
PRESET_FIELDS = {"description", "repository", "project_dir", "project_name", "program_name", "project_language", "project_cspec", "scripts"}
SCRIPT_FIELDS = {"description", "script_path", "script_name", "default_args"}
PROGRAM_SUFFIXES = (".exe", ".dll")


###########################################################
# Shared options
###########################################################

@pytest.mark.parametrize("flag", decompiler.no_pseudocode_checks)
def test_no_pseudocode_checks_are_long_flags(flag):
    assert flag.startswith("--no-")


def test_no_pseudocode_checks_are_unique():
    assert len(decompiler.no_pseudocode_checks) == len(set(decompiler.no_pseudocode_checks))


###########################################################
# Presets
###########################################################

@pytest.mark.parametrize("preset", [preset for _, preset in PRESETS], ids = PRESET_IDS)
def test_preset_has_every_required_field(preset):
    assert set(preset) == PRESET_FIELDS
    assert preset["program_name"].endswith(PROGRAM_SUFFIXES)
    assert preset["scripts"]


@pytest.mark.parametrize("preset", [preset for _, preset in PRESETS], ids = PRESET_IDS)
def test_preset_language_is_a_ghidra_language_id(preset):
    processor, endian, size, variant = preset["project_language"].split(":")
    assert processor and variant
    assert endian in ("LE", "BE")
    assert size.isdigit()


###########################################################
# Scripts
###########################################################

@pytest.mark.parametrize("preset_name, script_name, script", SCRIPTS, ids = SCRIPT_IDS)
def test_script_has_required_fields(preset_name, script_name, script):
    assert SCRIPT_FIELDS <= set(script) <= SCRIPT_FIELDS | {"program_name"}
    assert script["script_name"].endswith(".py")
    assert not script["script_path"].startswith("/")


@pytest.mark.parametrize("preset_name, script_name, script", SCRIPTS, ids = SCRIPT_IDS)
def test_script_default_args_are_strings(preset_name, script_name, script):
    assert all(isinstance(arg, str) and arg for arg in script["default_args"])


@pytest.mark.parametrize("preset_name, script_name, script", SCRIPTS, ids = SCRIPT_IDS)
def test_script_program_override_names_a_binary(preset_name, script_name, script):
    program_name = script.get("program_name", decompiler.decompiler_presets[preset_name]["program_name"])
    assert program_name.endswith(PROGRAM_SUFFIXES)


@pytest.mark.parametrize("preset_name, script_name, script", SCRIPTS, ids = SCRIPT_IDS)
def test_annotations_dir_matches_the_program_it_covers(preset_name, script_name, script):
    program_name = script.get("program_name", decompiler.decompiler_presets[preset_name]["program_name"])
    output_dirs = {arg for arg in script["default_args"] if arg.startswith("annotations/")}
    assert output_dirs <= {"annotations/", "annotations/" + program_name}
    assert ("annotations/" in output_dirs) == ("--all-programs" in script["default_args"])


@pytest.mark.parametrize("preset_name, script_name, script", SCRIPTS, ids = SCRIPT_IDS)
def test_pseudocode_is_compiled_only_for_the_preset_program(preset_name, script_name, script):
    preset_program = decompiler.decompiler_presets[preset_name]["program_name"]
    skips_checks = set(decompiler.no_pseudocode_checks) <= set(script["default_args"])
    assert skips_checks == (script.get("program_name", preset_program) != preset_program)
