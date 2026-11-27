# Third-party imports
import pytest

# Local imports
from joybox import config
from joybox import logger
from joybox.collection import scanning


###########################################################
# Building
#
# The steps run in pipeline order; skipping purchases narrows the metadata
# steps to the locker's games, and an unknown filter stops before any step.
###########################################################

STEPS = [
    "build_all_game_store_purchases",
    "build_all_game_json_files",
    "build_all_game_metadata_entries",
    "download_all_metadata_assets",
    "publish_all_game_metadata_entries",
]


@pytest.fixture
def steps(monkeypatch):
    calls = []
    for name in STEPS:
        def step(name = name, **kwargs):
            calls.append((name, kwargs))
            return True
        monkeypatch.setattr(scanning, name, step)
    return calls


def test_skipped_purchases_narrow_the_metadata_steps_to_the_locker(steps):
    scanning.scan_game_files(skip_purchases = True, download_assets = True)

    assert [name for name, _ in steps] == STEPS[1:]
    assert steps[1][1]["locker_type"] == config.LockerType.LOCAL
    assert steps[2][1]["skip_existing"] is True


def test_a_full_scan_leaves_the_metadata_steps_unnarrowed(steps):
    scanning.scan_game_files(categories = "Nintendo")

    assert [name for name, _ in steps] == [name for name in STEPS if name != "download_all_metadata_assets"]
    assert steps[2][1]["locker_type"] is None
    assert all(kwargs["categories"] == "Nintendo" for _, kwargs in steps)


def test_an_unknown_filter_value_stops_the_scan(monkeypatch):
    errors = []

    def log_error(message, quit_program = False):
        errors.append(message)
        raise SystemExit(1)
    monkeypatch.setattr(logger, "log_error", log_error)

    with pytest.raises(SystemExit):
        scanning.check_scan_filters(categories = "Nintendo, Atrai")
    assert errors == ["Unknown Category values: Atrai"]
