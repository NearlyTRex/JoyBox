# Imports
import os
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import system
from joybox.cli import decompiler_tool


###########################################################
# decompiler_tool
#
# The command picks listing, launching, a preset script or a manual script,
# and a run that fails or is missing what it needs exits with an error.
###########################################################

PRESETS = {
    "Decomp": {
        "description": "a decompilation",
        "scripts": {
            "export": {"description": "export everything"},
            "import": {"description": "import everything"},
        },
    },
    "Other": {"description": "another", "scripts": {"scan": {"description": "scan it"}}},
}


@pytest.fixture
def tool(monkeypatch):
    state = {"errors": [], "infos": [], "calls": [], "result": True}
    monkeypatch.setattr(decompiler_tool.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(decompiler_tool.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(decompiler_tool.logger, "log_error", state["errors"].append)
    monkeypatch.setattr(decompiler_tool.logger, "log_info", state["infos"].append)
    monkeypatch.setattr(decompiler_tool.decompiler.config, "decompiler_presets", PRESETS)

    def recorder(name):
        def record(**kwargs):
            state["calls"].append((name, kwargs))
            return state["result"]
        return record

    for name in ["launch_program", "run_script", "run_script_from_preset"]:
        monkeypatch.setattr(decompiler_tool.decompiler, name, recorder(name))

    def run(*argv):
        monkeypatch.setattr(sys, "argv", ["decompiler_tool", *argv])
        return decompiler_tool.main()

    state["run"] = run
    return state


@pytest.fixture
def manual(tmp_path):
    project_dir = tmp_path / "projects"
    project_dir.mkdir()
    script_path = tmp_path / "scripts"
    script_path.mkdir()
    return {"project_dir": str(project_dir), "script_path": str(script_path),
            "argv": ["-a", "RunScript", "-r", str(project_dir), "-n", "Project",
                     "-g", "game.exe", "--script_path", str(script_path),
                     "--script_name", "export.py"]}


###########################################################
# Listing
###########################################################

def test_listing_presets_runs_nothing(tool):
    assert tool["run"]("--list_presets") is True
    assert "  Decomp - a decompilation" in tool["infos"]
    assert "  Other - another" in tool["infos"]
    assert tool["calls"] == []


def test_listing_the_scripts_of_one_preset(tool):
    assert tool["run"]("--list_scripts", "--preset", "Decomp") is True
    assert "  export - export everything" in tool["infos"]
    assert "  scan - scan it" not in tool["infos"]
    assert tool["calls"] == []


def test_listing_the_scripts_of_every_preset(tool):
    assert tool["run"]("--list_scripts") is True
    assert tool["infos"] == [
        "Decomp:", "  export - export everything", "  import - import everything",
        "Other:", "  scan - scan it"]


def test_listing_the_scripts_of_an_unknown_preset_fails(tool):
    assert tool["run"]("--list_scripts", "--preset", "Missing") is False
    assert "Missing" in tool["errors"][0]


###########################################################
# Launching
###########################################################

@pytest.mark.parametrize("result", [True, False])
def test_launching_is_the_default_and_reports_its_result(tool, result):
    tool["result"] = result

    assert tool["run"]("-v", "-p") is result
    assert tool["calls"] == [("launch_program", {
        "verbose": True, "pretend_run": True, "exit_on_failure": False})]


###########################################################
# Preset mode
###########################################################

@pytest.mark.parametrize("result", [True, False])
def test_a_preset_script_runs_and_reports_its_result(tool, result):
    tool["result"] = result

    assert tool["run"]("-a", "RunScript", "--preset", "Decomp", "--script", "export",
        "--script_args", "out dir") is result
    assert tool["calls"] == [("run_script_from_preset", {
        "preset_name": "Decomp", "script_name": "export", "script_args": "out dir",
        "verbose": False, "pretend_run": False, "exit_on_failure": False})]


def test_a_preset_without_a_script_is_refused(tool):
    assert tool["run"]("-a", "RunScript", "--preset", "Decomp") is False
    assert "--script" in tool["errors"][0]
    assert tool["calls"] == []


###########################################################
# Manual mode
###########################################################

@pytest.mark.parametrize("result", [True, False])
def test_a_manual_script_runs_and_reports_its_result(tool, manual, result):
    tool["result"] = result

    assert tool["run"](*manual["argv"]) is result
    assert tool["calls"] == [("run_script", {
        "project_dir": os.path.realpath(manual["project_dir"]),
        "project_name": "Project", "program_name": "game.exe",
        "script_path": os.path.realpath(manual["script_path"]),
        "script_name": "export.py", "script_args": None,
        "verbose": False, "pretend_run": False, "exit_on_failure": False})]


@pytest.mark.parametrize("flag", ["-r", "-n", "-g", "--script_path", "--script_name"])
def test_a_manual_run_missing_an_option_explains_what_is_needed(tool, manual, flag):
    argv = list(manual["argv"])
    position = argv.index(flag)
    del argv[position:position + 2]

    assert tool["run"](*argv) is False
    assert "Manual mode requires" in tool["errors"][0]
    assert tool["calls"] == []


def test_a_failed_run_exits_with_an_error(tool, monkeypatch):
    tool["result"] = False
    monkeypatch.setattr(sys, "argv", ["decompiler_tool"])

    with pytest.raises(SystemExit) as raised:
        decompiler_tool.run()
    assert raised.value.code == 1


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", called.append)

    runpy.run_path(decompiler_tool.__file__, run_name = "__main__")

    assert len(called) == 1
