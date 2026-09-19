# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import config, decompiler


###########################################################
# Decompiler presets
#
# A preset names a repository, a Ghidra project and the scripts to run against
# it. resolve_preset_paths turns the relative entries into absolute ones, and
# a path resolved against the wrong root points the headless analyzer at
# nothing.
###########################################################

PRESET_NAMES = decompiler.get_decompiler_preset_names()


def test_presets_are_registered():
    assert len(PRESET_NAMES) > 0


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_a_preset_is_looked_up_by_name(preset_name):
    assert decompiler.get_decompiler_preset(preset_name) is not None


def test_an_unknown_preset_is_not_found():
    assert decompiler.get_decompiler_preset("not-a-preset") is None
    assert decompiler.resolve_preset_paths("not-a-preset") is None
    assert decompiler.get_preset_script_names("not-a-preset") == []
    assert decompiler.list_preset_scripts("not-a-preset") is None


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_preset_declares_its_project(preset_name):
    preset = decompiler.get_decompiler_preset(preset_name)

    for key in ["repository", "project_dir", "project_name", "description"]:
        assert preset.get(key), f"{preset_name} has no {key}"


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_preset_declares_scripts(preset_name):
    assert decompiler.get_preset_script_names(preset_name)


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_script_is_looked_up_by_name(preset_name):
    for script_name in decompiler.get_preset_script_names(preset_name):
        assert decompiler.get_preset_script(preset_name, script_name) is not None


def test_an_unknown_script_is_not_found():
    assert decompiler.get_preset_script(PRESET_NAMES[0], "not-a-script") is None


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_script_declares_a_path(preset_name):
    for script_name in decompiler.get_preset_script_names(preset_name):
        script = decompiler.get_preset_script(preset_name, script_name)
        assert script.get("script_path"), f"{preset_name}.{script_name} has no script_path"


###########################################################
# Resolution
###########################################################

@pytest.fixture
def repositories(isolated_settings):
    isolated_settings.set_value("UserData.Dirs", "repositories_dir", "/repos")
    return isolated_settings


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_the_repository_resolves_under_the_repositories_root(repositories, preset_name):
    resolved = decompiler.resolve_preset_paths(preset_name)

    assert resolved["repo_path"].startswith("/repos")


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_the_project_directory_resolves_under_the_repository(repositories, preset_name):
    resolved = decompiler.resolve_preset_paths(preset_name)

    assert resolved["project_dir_abs"].startswith(resolved["repo_path"])


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_script_path_resolves_under_the_repository(repositories, preset_name):
    resolved = decompiler.resolve_preset_paths(preset_name)

    for script_name, script in resolved["scripts"].items():
        assert script["script_path_abs"].startswith(resolved["repo_path"]), \
            f"{preset_name}.{script_name} resolves outside the repository"


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_resolution_keeps_the_original_entries(repositories, preset_name):
    preset = decompiler.get_decompiler_preset(preset_name)
    resolved = decompiler.resolve_preset_paths(preset_name)

    for key in preset:
        assert key in resolved


def test_resolution_does_not_modify_the_stored_preset(repositories):
    # The preset table is module state; resolving must not write into it.
    preset_name = PRESET_NAMES[0]
    before = dict(decompiler.get_decompiler_preset(preset_name))
    decompiler.resolve_preset_paths(preset_name)

    assert decompiler.get_decompiler_preset(preset_name) == before


def test_resolved_scripts_do_not_modify_the_stored_scripts(repositories):
    preset_name = PRESET_NAMES[0]
    script_name = decompiler.get_preset_script_names(preset_name)[0]
    before = dict(decompiler.get_preset_script(preset_name, script_name))

    decompiler.resolve_preset_paths(preset_name)

    assert decompiler.get_preset_script(preset_name, script_name) == before


def test_flag_arguments_are_left_alone(repositories):
    # A "-flag" must not be rewritten into a path.
    resolved = decompiler.resolve_preset_paths(PRESET_NAMES[0])

    for script in resolved["scripts"].values():
        for argument in script.get("default_args_abs", []):
            if argument.startswith("-"):
                assert not argument.startswith("/repos")


###########################################################
# Listings
###########################################################

def test_every_preset_is_listed_with_a_description():
    listed = decompiler.list_presets()

    assert len(listed) == len(PRESET_NAMES)
    for name, description in listed:
        assert name in PRESET_NAMES
        assert description


@pytest.mark.parametrize("preset_name", PRESET_NAMES)
def test_every_script_is_listed_with_a_description(preset_name):
    listed = decompiler.list_preset_scripts(preset_name)

    assert len(listed) == len(decompiler.get_preset_script_names(preset_name))
    for name, description in listed:
        assert description
