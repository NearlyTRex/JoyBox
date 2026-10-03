# Imports
import os

# Third-party imports
import pytest

# Local imports
from joybox import decompiler
from fakes import RecordingCommand


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


def test_a_script_of_an_unknown_preset_is_not_found():
    assert decompiler.get_preset_script("not-a-preset", "export_all") is None


###########################################################
# Presets without optional entries
###########################################################

@pytest.fixture
def bare_presets(repositories, monkeypatch):
    presets = {
        "NoScripts": {"repository": "Bare", "description": "no scripts"},
        "NoArgs": {
            "repository": "Bare",
            "scripts": {"plain": {"script_path": "scripts", "script_name": "plain.py"}},
        },
    }
    monkeypatch.setattr(decompiler.config, "decompiler_presets", presets)
    return presets


def test_a_preset_without_scripts_resolves_without_them(bare_presets):
    resolved = decompiler.resolve_preset_paths("NoScripts")

    assert resolved["project_dir_abs"] == "/repos/Bare/"
    assert "scripts" not in resolved
    assert decompiler.list_preset_scripts("NoScripts") == []


def test_a_script_without_default_args_gets_no_resolved_args(bare_presets):
    script = decompiler.resolve_preset_paths("NoArgs")["scripts"]["plain"]

    assert script["script_path_abs"] == "/repos/Bare/scripts"
    assert "default_args_abs" not in script


def test_missing_descriptions_are_listed_as_such(bare_presets):
    assert ("NoArgs", "No description") in decompiler.list_presets()
    assert decompiler.list_preset_scripts("NoArgs") == [("plain", "No description")]


###########################################################
# Running
#
# Both entry points run the venv Python with GHIDRA_INSTALL_DIR set; a script
# run must also force headless AWT so it never opens a display.
###########################################################

@pytest.fixture
def ghidra(tmp_path, monkeypatch):
    state = {"python": str(tmp_path / "python"), "installed": True,
             "ghidra": str(tmp_path / "Ghidra" / "lib"), "errors": []}
    os.makedirs(state["ghidra"])
    monkeypatch.setattr(decompiler.programs, "is_tool_installed",
        lambda name: name == "PythonVenvPython" and state["installed"])
    monkeypatch.setattr(decompiler.programs, "get_tool_program", lambda name: state["python"])
    monkeypatch.setattr(decompiler.programs, "get_library_install_dir",
        lambda name, platform: state["ghidra"])
    monkeypatch.setattr(decompiler.logger, "log_error", state["errors"].append)
    monkeypatch.delenv("JAVA_TOOL_OPTIONS", raising = False)
    state["command"] = RecordingCommand(monkeypatch)
    return state


@pytest.fixture
def project(tmp_path):
    project_dir = tmp_path / "projects"
    project_dir.mkdir()
    script_dir = tmp_path / "scripts"
    script_dir.mkdir()
    (script_dir / "export.py").write_text("")
    return {"project_dir": str(project_dir), "script_path": str(script_dir)}


def run_project_script(project, **kwargs):
    return decompiler.run_script(
        project_dir = project["project_dir"],
        project_name = "Project",
        program_name = "game.exe",
        script_path = project["script_path"],
        script_name = "export.py",
        **kwargs)


def test_launching_starts_pyghidra_with_the_ghidra_directory(ghidra):
    assert decompiler.launch_program(verbose = True) is True

    assert ghidra["command"].only() == [ghidra["python"], "-m", "pyghidra", "-g"]
    options = ghidra["command"].options()
    assert options.get_env_var("GHIDRA_INSTALL_DIR") == ghidra["ghidra"]


def test_a_failed_launch_is_reported(ghidra):
    ghidra["command"].returncode = 1

    assert decompiler.launch_program() is False


@pytest.mark.parametrize("run", [
    lambda project: decompiler.launch_program(),
    run_project_script,
])
def test_nothing_runs_without_the_venv_python(ghidra, project, run):
    ghidra["installed"] = False

    assert run(project) is False
    assert "PythonVenvPython" in ghidra["errors"][0]
    assert not ghidra["command"].ran()


@pytest.mark.parametrize("ghidra_dir", [None, "/nonexistent/Ghidra/lib"])
@pytest.mark.parametrize("run", [
    lambda project: decompiler.launch_program(),
    run_project_script,
])
def test_nothing_runs_without_ghidra(ghidra, project, run, ghidra_dir):
    ghidra["ghidra"] = ghidra_dir

    assert run(project) is False
    assert "Ghidra installation not found" in ghidra["errors"][0]
    assert not ghidra["command"].ran()


def test_a_script_runs_against_the_project(ghidra, project):
    assert run_project_script(project, verbose = True) is True

    assert ghidra["command"].only() == [
        ghidra["python"], os.path.join(project["script_path"], "export.py"),
        project["project_dir"], "Project", "game.exe"]
    options = ghidra["command"].options()
    assert options.get_env_var("GHIDRA_INSTALL_DIR") == ghidra["ghidra"]
    assert options.get_env_var("JAVA_TOOL_OPTIONS") == "-Djava.awt.headless=true"


def test_a_failed_script_is_reported(ghidra, project):
    ghidra["command"].returncode = 2

    assert run_project_script(project) is False


@pytest.mark.parametrize("script_args, tail", [
    (["out/", "--all"], ["out/", "--all"]),
    ("out dir", ["out dir"]),
    ([], []),
])
def test_script_arguments_follow_the_program_name(ghidra, project, script_args, tail):
    assert run_project_script(project, script_args = script_args, verbose = True) is True

    assert ghidra["command"].only()[5:] == tail


def test_existing_java_options_are_kept(ghidra, project, monkeypatch):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Xmx2g")

    run_project_script(project)

    assert ghidra["command"].options().get_env_var("JAVA_TOOL_OPTIONS") == \
        "-Xmx2g -Djava.awt.headless=true"


def test_headless_is_not_added_twice(ghidra, project, monkeypatch):
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-Djava.awt.headless=true")

    run_project_script(project)

    assert ghidra["command"].options().get_env_var("JAVA_TOOL_OPTIONS") == \
        "-Djava.awt.headless=true"


def test_a_missing_script_is_refused(ghidra, project):
    os.remove(os.path.join(project["script_path"], "export.py"))

    assert run_project_script(project) is False
    assert "Script not found" in ghidra["errors"][0]
    assert not ghidra["command"].ran()


def test_a_missing_project_directory_is_refused(ghidra, project):
    os.rmdir(project["project_dir"])

    assert run_project_script(project) is False
    assert "Project directory not found" in ghidra["errors"][0]
    assert not ghidra["command"].ran()


###########################################################
# Running from a preset
###########################################################

@pytest.fixture
def preset_repository(ghidra, isolated_settings, tmp_path, monkeypatch):
    isolated_settings.set_value("UserData.Dirs", "repositories_dir", str(tmp_path))
    repo = tmp_path / "Decomp"
    (repo / "projects").mkdir(parents = True)
    (repo / "scripts").mkdir()
    (repo / "scripts" / "export.py").write_text("")
    presets = {
        "Decomp": {
            "repository": "Decomp",
            "project_dir": "projects",
            "project_name": "Project",
            "program_name": "main.exe",
            "scripts": {
                "export": {"script_path": "scripts", "script_name": "export.py",
                           "default_args": ["out/main", "--all"]},
                "export_dll": {"script_path": "scripts", "script_name": "export.py",
                               "program_name": "lib.dll"},
            },
        },
    }
    monkeypatch.setattr(decompiler.config, "decompiler_presets", presets)
    return str(repo)


def test_a_preset_script_runs_with_its_resolved_default_args(ghidra, preset_repository):
    assert decompiler.run_script_from_preset("Decomp", "export") is True

    assert ghidra["command"].only() == [
        ghidra["python"], os.path.join(preset_repository, "scripts", "export.py"),
        os.path.join(preset_repository, "projects"), "Project", "main.exe",
        os.path.join(preset_repository, "out/main"), "--all"]


def test_given_arguments_replace_the_defaults(ghidra, preset_repository):
    assert decompiler.run_script_from_preset("Decomp", "export", script_args = "elsewhere") is True

    assert ghidra["command"].only()[5:] == ["elsewhere"]


def test_a_script_may_override_the_program(ghidra, preset_repository):
    assert decompiler.run_script_from_preset("Decomp", "export_dll") is True

    assert ghidra["command"].only()[4:] == ["lib.dll"]


def test_an_unknown_preset_is_not_run(ghidra, preset_repository):
    assert decompiler.run_script_from_preset("Missing", "export") is False
    assert "Missing" in ghidra["errors"][0]
    assert not ghidra["command"].ran()


def test_an_unknown_preset_script_is_not_run(ghidra, preset_repository):
    assert decompiler.run_script_from_preset("Decomp", "missing") is False
    assert "missing" in ghidra["errors"][0]
    assert not ghidra["command"].ran()
