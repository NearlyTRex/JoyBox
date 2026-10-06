# Third-party imports
import pytest

# Local imports
from cli_helpers import CommandHarness, assert_entry_points
from joybox.cli import publish_game_metadata_files


###########################################################
# Publishing
###########################################################

@pytest.fixture
def tool(monkeypatch):
    harness = CommandHarness(monkeypatch, publish_game_metadata_files)
    harness.published = []
    harness.result = True
    monkeypatch.setattr(publish_game_metadata_files.environment, "get_game_published_metadata_root_dir", lambda: "/published")

    def publish(**kwargs):
        harness.published.append(kwargs)
        return harness.result

    monkeypatch.setattr(publish_game_metadata_files.collection, "publish_all_game_metadata_entries", publish)
    return harness


def test_the_preview_names_the_publish_directory(tool):
    tool.run("-v")

    assert tool.previews == [("Publish game metadata files to HTML", ["/published"])]
    assert tool.published == [{"verbose": True, "pretend_run": False, "exit_on_failure": False}]


def test_a_declined_preview_publishes_nothing(tool):
    tool.confirm = False

    tool.run()

    assert tool.published == []
    assert tool.warnings == ["Operation cancelled by user"]


def test_a_failed_publish_exits_with_an_error(tool):
    tool.result = False

    assert tool.exit_code("--no-preview") != 0
    assert tool.errors == ["Publishing metadata files failed"]


def test_running_the_module_starts_the_command(monkeypatch):
    assert_entry_points(monkeypatch, publish_game_metadata_files)
