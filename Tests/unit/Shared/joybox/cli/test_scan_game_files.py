# Imports
import runpy
import sys

# Third-party imports
import pytest

# Local imports
from joybox import config, system
from joybox.cli import scan_game_files


###########################################################
# Pipeline order and failure
#
# Each step feeds the next, so a failed step must stop the run with a non-zero
# exit instead of publishing stale metadata.
###########################################################

STEPS = [
    "build_all_game_store_purchases",
    "build_all_game_json_files",
    "build_all_game_metadata_entries",
    "download_all_metadata_assets",
    "publish_all_game_metadata_entries",
]


class FakeManifest:

    def __init__(self, state):
        self.state = state

    def load(self, **kwargs):
        self.state["called"].append("load_manifest")


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    state = {"called": [], "kwargs": {}, "failing": None, "confirm": True, "errors": []}
    monkeypatch.setattr(scan_game_files.setup, "check_requirements", lambda: None)
    monkeypatch.setattr(scan_game_files.logger, "setup_logging", lambda: None)
    monkeypatch.setattr(scan_game_files.manifest, "get_manifest_instance", lambda: FakeManifest(state))
    monkeypatch.setattr(scan_game_files.prompts, "prompt_for_preview", lambda operation, details: state["confirm"])
    for name in STEPS:
        def step(name = name, **kwargs):
            state["called"].append(name)
            state["kwargs"][name] = kwargs
            return name != state["failing"]
        monkeypatch.setattr(scan_game_files.collection, name, step)
    log_error = scan_game_files.logger.log_error

    def record_error(message, **kwargs):
        state["errors"].append(message)
        log_error(message, **kwargs)

    monkeypatch.setattr(scan_game_files.logger, "log_error", record_error)

    def run(*extra):
        monkeypatch.setattr(sys, "argv", ["scan_game_files", *extra])
        return system.run_main(scan_game_files.main)

    state["run"] = run
    return state


def test_default_run_skips_manifest_and_assets(tool):
    tool["run"]("--no-preview")

    assert tool["called"] == [
        "build_all_game_store_purchases",
        "build_all_game_json_files",
        "build_all_game_metadata_entries",
        "publish_all_game_metadata_entries",
    ]


def test_every_step_gets_the_selection(tool):
    tool["run"]("-m", "-a", "-l", "Local", "-c", "Nintendo,Sony", "-s", "Nintendo Switch")

    assert tool["called"] == ["load_manifest"] + STEPS
    for name in STEPS:
        assert tool["kwargs"][name]["categories"] == "Nintendo,Sony"
        assert tool["kwargs"][name]["subcategories"] == "Nintendo Switch"
    assert tool["kwargs"]["build_all_game_json_files"]["locker_type"] == config.LockerType.LOCAL
    assert tool["kwargs"]["download_all_metadata_assets"]["skip_existing"] is True


def test_declined_preview_runs_nothing(tool):
    tool["confirm"] = False

    tool["run"]("-m")

    assert tool["called"] == []


@pytest.mark.parametrize("failing, message", [
    ("build_all_game_store_purchases", "Building store purchases failed"),
    ("build_all_game_json_files", "Building json files failed"),
    ("build_all_game_metadata_entries", "Building metadata files failed"),
    ("download_all_metadata_assets", "Downloading metadata assets failed"),
    ("publish_all_game_metadata_entries", "Publishing metadata files failed"),
])
def test_a_failed_step_stops_the_pipeline(tool, failing, message):
    tool["failing"] = failing

    with pytest.raises(SystemExit) as raised:
        tool["run"]("--no-preview", "-a")
    assert raised.value.code != 0
    assert tool["errors"] == [message]
    assert tool["called"] == STEPS[:STEPS.index(failing) + 1]


@pytest.mark.parametrize("option, value, message", [
    ("-c", "Nintendo,Nintnedo", "Unknown Category values: Nintnedo"),
    ("-s", "Nintendo Switch, Stema", "Unknown Subcategory values: Stema"),
])
def test_a_misspelled_filter_quits_instead_of_scanning_everything(tool, option, value, message):
    with pytest.raises(SystemExit) as raised:
        tool["run"]("--no-preview", option, value)
    assert raised.value.code != 0
    assert tool["errors"] == [message]
    assert tool["called"] == []


def test_run_goes_through_the_shared_error_handling(tool, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["scan_game_files", "--no-preview"])

    scan_game_files.run()

    assert len(tool["called"]) == 4


def test_running_the_module_starts_the_command(monkeypatch):
    called = []
    monkeypatch.setattr(system, "run_main", lambda main: called.append(main))

    runpy.run_path(scan_game_files.__file__, run_name = "__main__")

    assert len(called) == 1
