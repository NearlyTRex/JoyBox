# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
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

    def __init__(self, harness):
        self.harness = harness

    def load(self, **kwargs):
        self.harness.called.append("load_manifest")


@pytest.fixture
def tool(monkeypatch, isolated_settings):
    harness = CommandHarness(monkeypatch, scan_game_files)
    harness.called = []
    harness.kwargs = {}
    harness.failing = None
    monkeypatch.setattr(scan_game_files.manifest, "get_manifest_instance", lambda: FakeManifest(harness))
    for name in STEPS:
        def step(name = name, **kwargs):
            harness.called.append(name)
            harness.kwargs[name] = kwargs
            return name != harness.failing
        monkeypatch.setattr(scan_game_files.collection, name, step)
    return harness


def test_default_run_skips_manifest_and_assets(tool):
    tool.run("--no-preview")

    assert tool.called == [
        "build_all_game_store_purchases",
        "build_all_game_json_files",
        "build_all_game_metadata_entries",
        "publish_all_game_metadata_entries",
    ]


def test_every_step_gets_the_selection(tool):
    tool.run("-m", "-a", "-l", "Local", "-c", "Nintendo,Sony", "-s", "Nintendo Switch")

    assert tool.called == ["load_manifest"] + STEPS
    for name in STEPS:
        assert tool.kwargs[name]["categories"] == "Nintendo,Sony"
        assert tool.kwargs[name]["subcategories"] == "Nintendo Switch"
    assert tool.kwargs["build_all_game_json_files"]["locker_type"] == config.LockerType.LOCAL
    assert tool.kwargs["download_all_metadata_assets"]["skip_existing"] is True


def test_declined_preview_runs_nothing(tool):
    tool.confirm = False

    tool.run("-m")

    assert tool.called == []


@pytest.mark.parametrize("failing, message", [
    ("build_all_game_store_purchases", "Building store purchases failed"),
    ("build_all_game_json_files", "Building json files failed"),
    ("build_all_game_metadata_entries", "Building metadata files failed"),
    ("download_all_metadata_assets", "Downloading metadata assets failed"),
    ("publish_all_game_metadata_entries", "Publishing metadata files failed"),
])
def test_a_failed_step_stops_the_pipeline(tool, failing, message):
    tool.failing = failing

    assert tool.exit_code("--no-preview", "-a") != 0
    assert tool.errors == [message]
    assert tool.called == STEPS[:STEPS.index(failing) + 1]


@pytest.mark.parametrize("option, value, message", [
    ("-c", "Nintendo,Nintnedo", "Unknown Category values: Nintnedo"),
    ("-s", "Nintendo Switch, Stema", "Unknown Subcategory values: Stema"),
])
def test_a_misspelled_filter_quits_instead_of_scanning_everything(tool, option, value, message):
    assert tool.exit_code("--no-preview", option, value) != 0
    assert tool.errors == [message]
    assert tool.called == []


def test_run_goes_through_the_shared_error_handling(tool):
    tool.run("--no-preview")

    assert len(tool.called) == 4


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, scan_game_files)
