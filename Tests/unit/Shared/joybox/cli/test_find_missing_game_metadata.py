# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox import config
from joybox.cli import find_missing_game_metadata


###########################################################
# Missing keys
#
# An entry counts as missing a key when the key is unset or empty; one
# report is written per key that some entry lacks.
###########################################################

class FakeEntry:

    def __init__(self, name, values):
        self.name = name
        self.values = values

    def get_game(self):
        return self.name

    def is_key_set(self, key):
        return key in self.values

    def get_value(self, key):
        return self.values[key]


FULL = {key: "set" for key in config.metadata_keys_all}
ENTRIES = {
    "Nintendo Switch": [
        FakeEntry("Alpha", FULL),
        FakeEntry("Beta", {**FULL, config.metadata_key_description: ""}),
        FakeEntry("Gamma", {key: value for key, value in FULL.items() if key != config.metadata_key_genre}),
    ],
}


class FakeMetadata:

    def get_sorted_platforms(self):
        return sorted(ENTRIES)

    def get_sorted_entries(self, platform):
        return ENTRIES[platform]


@pytest.fixture
def tool(monkeypatch, isolated_settings, tmp_path):
    harness = CommandHarness(monkeypatch, find_missing_game_metadata)
    harness.reports = []
    harness.loaded = []
    module = find_missing_game_metadata
    metadata_dir = tmp_path / "Pegasus"
    (metadata_dir / "Switch").mkdir(parents = True)
    (metadata_dir / "Switch" / "metadata.pegasus.txt").write_text("")
    (metadata_dir / "Switch" / "notes.txt").write_text("")
    monkeypatch.setattr(FakeMetadata, "import_from_metadata_file", lambda self, filename: harness.loaded.append(filename), raising = False)
    monkeypatch.setattr(module.environment, "get_game_pegasus_metadata_root_dir", lambda: str(metadata_dir))
    monkeypatch.setattr(module.metadata, "Metadata", FakeMetadata)
    monkeypatch.setattr(module.reports, "write_list_report", lambda **kwargs: harness.reports.append(kwargs))
    return harness


def reported(tool):
    return {call["report_file"]: call["items"] for call in tool.reports}


def test_unset_and_empty_keys_are_reported_per_key(tool):
    tool.run("--no-preview")

    assert reported(tool) == {
        "Missing_%s.txt" % config.metadata_key_description: ["Nintendo Switch - Beta"],
        "Missing_%s.txt" % config.metadata_key_genre: ["Nintendo Switch - Gamma"],
    }
    assert len(tool.loaded) == 1
    assert tool.loaded[0].endswith("metadata.pegasus.txt")


def test_minimum_keys_ignore_the_downloadable_ones(tool):
    tool.run("--no-preview", "-k", "Minimum")

    assert tool.reports == []


def test_all_keys_include_the_downloadable_ones(tool):
    tool.run("--no-preview", "-k", "All", "-v")

    assert len(tool.reports) == 2
    assert {call["max_display"] for call in tool.reports} == {10}



def test_the_preview_lists_the_keys(tool):
    tool.run("-k", "Minimum")

    [(_, details)] = tool.previews
    assert details[1] == "Keys to check: %s" % ", ".join(config.metadata_keys_minimum)


def test_a_cancelled_preview_scans_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.loaded == []


def test_entry_points_run_main(monkeypatch):
    assert_entry_points(monkeypatch, find_missing_game_metadata)
